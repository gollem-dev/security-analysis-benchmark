package bench

import (
	"fmt"
	"path/filepath"

	"github.com/m-mizutani/goerr/v2"
)

// Source is one result to merge and the directory its file was read from, which its trace paths
// are relative to.
type Source struct {
	Result *Result
	Dir    string
}

// Merge puts several results into one written to outDir. A scenario is merged only when every
// result that has it measured the same version of the same content; otherwise it is left out with
// the reason, so every candidate's scores rest on the same scenarios. A candidate named in more than
// one result is renamed <name>@<run_id>. Trace paths are rewritten to be relative to outDir, the
// traces themselves staying where they are.
func Merge(sources []Source, outDir string) (*Result, error) {
	if len(sources) == 0 {
		return nil, goerr.New("there is no result to merge")
	}
	first := sources[0].Result
	out := &Result{FormatVersion: FormatVersion, RunID: first.RunID, Commit: first.Commit, Branch: first.Branch,
		StartedAt: first.StartedAt, FinishedAt: first.FinishedAt, MaxUSD: first.MaxUSD, Plan: first.Plan}

	names := map[string]int{}
	for _, s := range sources {
		for _, c := range s.Result.Candidates {
			names[c.Name]++
		}
	}
	rename := func(r *Result, name string) string {
		if names[name] > 1 {
			return name + "@" + r.RunID
		}
		return name
	}

	type key struct {
		role Role
		id   string
	}
	var roleOrder []Role
	roles := map[Role]*RoleResult{}
	var scenarioOrder []key
	scenarios := map[key]*ScenarioResult{}
	excluded := map[key]bool{}
	for _, src := range sources {
		r := src.Result
		for _, rr := range r.Roles {
			if _, ok := roles[rr.Role]; !ok {
				roleOrder = append(roleOrder, rr.Role)
				roles[rr.Role] = &RoleResult{Role: rr.Role}
			}
			for _, s := range rr.Scenarios {
				k := key{rr.Role, s.ID}
				if excluded[k] {
					continue
				}
				merged, ok := scenarios[k]
				if !ok {
					scenarioOrder = append(scenarioOrder, k)
					copied := s
					copied.Trials, copied.Tallies = nil, nil
					merged = &copied
					scenarios[k] = merged
				}
				if s.Version != merged.Version || (s.Hash != "" && merged.Hash != "" && s.Hash != merged.Hash) {
					excluded[k] = true
					out.Excluded = append(out.Excluded, ExcludedScenario{Role: rr.Role, Scenario: s.ID,
						Reason: fmt.Sprintf("the scenario's content differs between runs (version %d and %d)", merged.Version, s.Version)})
					continue
				}
				for _, t := range s.Trials {
					t.Candidate = rename(r, t.Candidate)
					if t.Trace != "" {
						trace, err := relocate(src.Dir, t.Trace, outDir)
						if err != nil {
							return nil, err
						}
						t.Trace = trace
					}
					merged.Trials = append(merged.Trials, t)
				}
				for _, t := range s.Tallies {
					t.Candidate = rename(r, t.Candidate)
					merged.Tallies = append(merged.Tallies, t)
				}
			}
		}
		for _, c := range r.Candidates {
			c.Name = rename(r, c.Name)
			if c.RunID == "" {
				c.RunID = r.RunID
			}
			out.Candidates = append(out.Candidates, c)
		}
		out.Forecast = append(out.Forecast, r.Forecast...)
		out.SpentNanoUSD += r.SpentNanoUSD
		if r.BudgetViolation != nil && out.BudgetViolation == nil {
			out.BudgetViolation = r.BudgetViolation
		}
		out.Runs = append(out.Runs, r.Runs...)
		// A merged result read back keeps the scenarios its own merge left out.
		out.Excluded = append(out.Excluded, r.Excluded...)
	}
	for _, k := range scenarioOrder {
		if !excluded[k] {
			roles[k.role].Scenarios = append(roles[k.role].Scenarios, *scenarios[k])
		}
	}
	for _, role := range roleOrder {
		if len(roles[role].Scenarios) > 0 {
			out.Roles = append(out.Roles, *roles[role])
		}
	}
	return out, nil
}

// relocate is the path, relative to outDir, of trace written relative to dir.
func relocate(dir, trace, outDir string) (string, error) {
	from, err := filepath.Abs(filepath.Join(dir, filepath.FromSlash(trace)))
	if err != nil {
		return "", goerr.Wrap(err, "failed to resolve a trace directory", goerr.V("trace", trace), goerr.V("dir", dir))
	}
	to, err := filepath.Abs(outDir)
	if err != nil {
		return "", goerr.Wrap(err, "failed to resolve the output directory", goerr.V("out", outDir))
	}
	rel, err := filepath.Rel(to, from)
	if err != nil {
		return "", goerr.Wrap(err, "failed to relate a trace to the output directory",
			goerr.V("trace", from), goerr.V("out", to))
	}
	return filepath.ToSlash(rel), nil
}
