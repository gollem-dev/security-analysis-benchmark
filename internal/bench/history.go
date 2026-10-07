package bench

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/m-mizutani/goerr/v2"
)

// Wanted is a candidate a report built from saved results shows, as the configuration names it.
type Wanted struct {
	Name, Provider, Model string
	Roles                 []Role
	// Current is the roles the configuration names the candidate the baseline of.
	Current []Role
}

// Pick chooses, for every wanted candidate, the newest saved measurement of the same name, provider
// and model that covers every scenario of current on the candidate's roles at the scenario's current
// version, and returns the sources narrowed to the candidates chosen from them, the newest first, so
// a merge of them shows each wanted candidate once. A measurement of only some of those scenarios,
// or of an earlier version of one, is passed over: its scores would rest on other scenarios than the
// other candidates'. A candidate's baseline roles are the configuration's, among the roles it was
// measured on. missing lists the wanted candidates no source measured so.
func Pick(sources []Source, wanted []Wanted, current []Scenario) (picked []Source, missing []string) {
	type choice struct {
		source  int
		started time.Time
	}
	chosen := map[string]choice{}
	for i, s := range sources {
		for _, c := range s.Result.Candidates {
			w := slices.IndexFunc(wanted, func(w Wanted) bool { return w.Name == c.Name && w.Provider == c.Provider && w.Model == c.Model })
			if w < 0 || !s.Result.covers(c.Name, wanted[w].Roles, current) {
				continue
			}
			started := s.Result.startedOf(c)
			if prev, ok := chosen[c.Name]; !ok || started.After(prev.started) {
				chosen[c.Name] = choice{i, started}
			}
		}
	}
	names := map[int][]string{}
	for _, w := range wanted {
		ch, ok := chosen[w.Name]
		if !ok {
			missing = append(missing, w.Name)
			continue
		}
		names[ch.source] = append(names[ch.source], w.Name)
	}
	for i, s := range sources {
		if len(names[i]) == 0 {
			continue
		}
		r := Narrow(s.Result, names[i])
		for j, c := range r.Candidates {
			w := wanted[slices.IndexFunc(wanted, func(w Wanted) bool { return w.Name == c.Name })]
			r.Candidates[j].Current = slices.DeleteFunc(slices.Clone(w.Current), func(role Role) bool { return !slices.Contains(c.Roles, role) })
		}
		picked = append(picked, Source{Result: r, Dir: s.Dir})
	}
	newest := func(s Source) time.Time {
		var t time.Time
		for _, c := range s.Result.Candidates {
			if st := s.Result.startedOf(c); st.After(t) {
				t = st
			}
		}
		return t
	}
	slices.SortStableFunc(picked, func(a, b Source) int { return newest(b).Compare(newest(a)) })
	return picked, missing
}

// covers is whether r measured the candidate on every scenario of current on the roles, at the
// scenario's version: r has the scenario and the candidate's tally of it, or the scenario's failure
// to be prepared, which no candidate could be measured on.
func (r *Result) covers(candidate string, roles []Role, current []Scenario) bool {
	for _, want := range current {
		role := want.Kind.Role()
		if !slices.Contains(roles, role) {
			continue
		}
		found := false
		for _, rr := range r.Roles {
			if rr.Role != role {
				continue
			}
			for _, s := range rr.Scenarios {
				if s.ID != want.ID || s.Version != want.Version {
					continue
				}
				_, tallied := s.Tally(candidate)
				found = tallied || s.Failure != ""
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// startedOf is when the run that measured c started: its run's manifest's time, else the result's.
func (r *Result) startedOf(c Candidate) time.Time {
	runID := cmp.Or(c.RunID, r.RunID)
	for _, m := range r.Runs {
		if m.RunID == runID {
			return m.StartedAt
		}
	}
	return r.StartedAt
}

// Narrow is a copy of r with only the named candidates: their trials, tallies and forecast, the roles
// one of them was measured on, and the runs they were measured in. When a candidate is left out, the
// spending is what the kept candidates' trials cost, since the ledger's total cannot be divided
// between candidates.
func Narrow(r *Result, names []string) *Result {
	out := *r
	out.Candidates, out.Roles, out.Forecast, out.Runs = nil, nil, nil, nil
	runs := map[string]bool{}
	roles := map[Role]bool{}
	var cost int64
	for _, c := range r.Candidates {
		if !slices.Contains(names, c.Name) {
			continue
		}
		c.Roles, c.Current = slices.Clone(c.Roles), slices.Clone(c.Current)
		out.Candidates = append(out.Candidates, c)
		runs[cmp.Or(c.RunID, r.RunID)] = true
		for _, role := range c.Roles {
			roles[role] = true
		}
		cost += c.CostNanoUSD
	}
	if len(out.Candidates) < len(r.Candidates) {
		out.SpentNanoUSD = cost
	}
	for _, rr := range r.Roles {
		if !roles[rr.Role] {
			continue
		}
		kept := RoleResult{Role: rr.Role}
		for _, s := range rr.Scenarios {
			s.Trials = slices.DeleteFunc(slices.Clone(s.Trials), func(t TrialResult) bool { return !slices.Contains(names, t.Candidate) })
			s.Tallies = slices.DeleteFunc(slices.Clone(s.Tallies), func(t CandidateTally) bool { return !slices.Contains(names, t.Candidate) })
			kept.Scenarios = append(kept.Scenarios, s)
		}
		out.Roles = append(out.Roles, kept)
	}
	for _, f := range r.Forecast {
		if slices.Contains(names, f.Candidate) {
			out.Forecast = append(out.Forecast, f)
		}
	}
	for _, m := range r.Runs {
		if runs[m.RunID] {
			out.Runs = append(out.Runs, m)
		}
	}
	return &out
}

// ForHistory is the copy of r a history keeps: its trials name no trace, since the traces are not
// kept with it, and redact is applied to the errors of its scenarios and trials, the text that
// providers and the environment write.
func ForHistory(r *Result, redact func(string) string) *Result {
	out := *r
	out.Traces = nil
	out.Roles = make([]RoleResult, len(r.Roles))
	for i, rr := range r.Roles {
		out.Roles[i] = RoleResult{Role: rr.Role, Scenarios: make([]ScenarioResult, len(rr.Scenarios))}
		for j, s := range rr.Scenarios {
			s.Failure = redact(s.Failure)
			s.Trials = slices.Clone(s.Trials)
			for k := range s.Trials {
				s.Trials[k].Trace = ""
				s.Trials[k].Error = redact(s.Trials[k].Error)
			}
			out.Roles[i].Scenarios[j] = s
		}
	}
	return &out
}

// HistoryExt is the extension of a result file in a history directory.
const HistoryExt = ".json"

// HistoryPath is the file of r in the history directory dir: one file per run, named by its run ID.
func HistoryPath(dir string, r *Result) string {
	return filepath.Join(dir, r.RunID+HistoryExt)
}

// ReadHistory reads every result file of the history directory dir, in the order of their names.
func ReadHistory(dir string) ([]Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to read the history directory", goerr.V("history", dir))
	}
	var out []Source
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), HistoryExt) {
			continue
		}
		r, err := ReadResult(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, Source{Result: r, Dir: dir})
	}
	return out, nil
}
