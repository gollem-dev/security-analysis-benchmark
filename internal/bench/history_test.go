package bench_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
)

// measured is a run that started at the given hour and measured each named candidate on api-named
// as a worker, with gemini-3.8-flash.
func measured(id string, hour int, names ...string) *bench.Result {
	started := time.Date(2026, 10, 1, hour, 0, 0, 0, time.UTC)
	r := &bench.Result{FormatVersion: bench.FormatVersion, RunID: id, StartedAt: started, SpentNanoUSD: 1000,
		Runs: []bench.RunManifest{{RunID: id, StartedAt: started}}}
	s := bench.ScenarioResult{ID: "api-named", Kind: bench.KindAPI, Version: 1}
	for _, n := range names {
		r.Candidates = append(r.Candidates, bench.Candidate{Name: n, Provider: "gemini", Model: "gemini-3.8-flash",
			Roles: []bench.Role{bench.RoleWorker}, RunID: id, CostNanoUSD: 10})
		s.Trials = append(s.Trials, bench.TrialResult{Candidate: n, Trial: 1, Trace: "traces/worker/api-named/" + n + "/1"})
		s.Tallies = append(s.Tallies, bench.CandidateTally{Candidate: n, Trials: 1})
		r.Forecast = append(r.Forecast, bench.ForecastLine{Candidate: n, Role: bench.RoleWorker, Scenario: "api-named"})
	}
	r.Roles = []bench.RoleResult{{Role: bench.RoleWorker, Scenarios: []bench.ScenarioResult{s}}}
	return r
}

func wanted(names ...string) []bench.Wanted {
	var out []bench.Wanted
	for _, n := range names {
		out = append(out, bench.Wanted{Name: n, Provider: "gemini", Model: "gemini-3.8-flash", Roles: []bench.Role{bench.RoleWorker}})
	}
	return out
}

// current is the scenarios as they are now: api-named at version 1.
var current = []bench.Scenario{{ID: "api-named", Kind: bench.KindAPI, Version: 1}}

func candidateNames(r *bench.Result) []string {
	var out []string
	for _, c := range r.Candidates {
		out = append(out, c.Name)
	}
	return out
}

func TestPickTakesEachCandidatesNewestMeasurement(t *testing.T) {
	old := measured("old", 1, "a", "b")
	recent := measured("recent", 2, "a")
	picked, missing := bench.Pick([]bench.Source{{Result: old}, {Result: recent}}, wanted("a", "b", "c"), current)
	gt.A(t, missing).Equal([]string{"c"})
	gt.A(t, picked).Length(2).Required()
	// The newest first, each narrowed to the candidates taken from it.
	gt.S(t, picked[0].Result.RunID).Equal("recent")
	gt.A(t, candidateNames(picked[0].Result)).Equal([]string{"a"})
	gt.S(t, picked[1].Result.RunID).Equal("old")
	gt.A(t, candidateNames(picked[1].Result)).Equal([]string{"b"})
	gt.A(t, picked[1].Result.Roles[0].Scenarios[0].Trials).Length(1).Required()
	gt.S(t, picked[1].Result.Roles[0].Scenarios[0].Trials[0].Candidate).Equal("b")

	merged, err := bench.Merge(picked, t.TempDir())
	gt.NoError(t, err).Required()
	gt.A(t, candidateNames(merged)).Equal([]string{"a", "b"})
	gt.A(t, merged.Runs).Length(2)
	gt.S(t, merged.RunID).Equal("recent")
}

// A measurement of another model under the same name is not the configured candidate's.
func TestPickNeedsTheSameProviderAndModel(t *testing.T) {
	r := measured("r", 1, "a")
	w := wanted("a")
	w[0].Model = "gemini-3.1-pro-preview"
	picked, missing := bench.Pick([]bench.Source{{Result: r}}, w, current)
	gt.A(t, picked).Length(0)
	gt.A(t, missing).Equal([]string{"a"})
}

// A newer measurement of only some of the scenarios, or of an earlier version of one, does not stand
// for the candidate.
func TestPickPassesOverAMeasurementOfOtherScenarios(t *testing.T) {
	both := []bench.Scenario{current[0], {ID: "sql-named", Kind: bench.KindSQL, Version: 2}}
	full := measured("full", 1, "a")
	full.Roles[0].Scenarios = append(full.Roles[0].Scenarios, bench.ScenarioResult{ID: "sql-named", Kind: bench.KindSQL, Version: 2,
		Tallies: []bench.CandidateTally{{Candidate: "a", Trials: 1}}})
	partial := measured("partial", 2, "a")
	outdated := measured("outdated", 3, "a")
	outdated.Roles[0].Scenarios = append(outdated.Roles[0].Scenarios, bench.ScenarioResult{ID: "sql-named", Kind: bench.KindSQL, Version: 1,
		Tallies: []bench.CandidateTally{{Candidate: "a", Trials: 1}}})
	picked, missing := bench.Pick([]bench.Source{{Result: full}, {Result: partial}, {Result: outdated}}, wanted("a"), both)
	gt.A(t, missing).Length(0)
	gt.A(t, picked).Length(1).Required()
	gt.S(t, picked[0].Result.RunID).Equal("full")

	// No measurement of every scenario: the candidate is missing.
	_, missing = bench.Pick([]bench.Source{{Result: partial}, {Result: outdated}}, wanted("a"), both)
	gt.A(t, missing).Equal([]string{"a"})

	// A scenario that could not be prepared was measured as far as it could be.
	failed := measured("failed", 4, "a")
	failed.Roles[0].Scenarios = append(failed.Roles[0].Scenarios, bench.ScenarioResult{ID: "sql-named", Kind: bench.KindSQL, Version: 2,
		Failure: "the emulator did not start"})
	picked, _ = bench.Pick([]bench.Source{{Result: full}, {Result: failed}}, wanted("a"), both)
	gt.A(t, picked).Length(1).Required()
	gt.S(t, picked[0].Result.RunID).Equal("failed")

	// Only the candidate's roles count: an orchestrator scenario does not concern a worker.
	withOrchestrator := append(slices.Clone(current), bench.Scenario{ID: "investigate-insider", Kind: bench.KindInvestigate, Version: 1})
	picked, _ = bench.Pick([]bench.Source{{Result: partial}}, wanted("a"), withOrchestrator)
	gt.A(t, picked).Length(1)
}

func TestPickTakesTheBaselineFromTheConfiguration(t *testing.T) {
	r := measured("r", 1, "a", "b")
	r.Candidates[0].Current = []bench.Role{bench.RoleWorker}
	w := wanted("a", "b")
	w[1].Current = []bench.Role{bench.RoleOrchestrator, bench.RoleWorker}
	picked, _ := bench.Pick([]bench.Source{{Result: r}}, w, current)
	gt.A(t, picked).Length(1).Required()
	gt.A(t, picked[0].Result.Candidates[0].Current).Length(0)
	// The orchestrator is left out: b was not measured on it.
	gt.A(t, picked[0].Result.Candidates[1].Current).Equal([]bench.Role{bench.RoleWorker})
}

func TestNarrowKeepsOnlyTheNamedCandidates(t *testing.T) {
	r := measured("r", 1, "a", "b")
	n := bench.Narrow(r, []string{"b"})
	gt.A(t, candidateNames(n)).Equal([]string{"b"})
	gt.A(t, n.Forecast).Length(1).Required()
	gt.S(t, n.Forecast[0].Candidate).Equal("b")
	gt.A(t, n.Roles[0].Scenarios[0].Tallies).Length(1)
	gt.N(t, n.SpentNanoUSD).Equal(int64(10))
	gt.A(t, n.Runs).Length(1)
	// r itself is unchanged.
	gt.A(t, r.Roles[0].Scenarios[0].Trials).Length(2)
	gt.A(t, r.Candidates).Length(2)

	gt.N(t, bench.Narrow(r, []string{"a", "b"}).SpentNanoUSD).Equal(int64(1000))
}

func TestARoleNoKeptCandidateHasIsLeftOut(t *testing.T) {
	r := measured("r", 1, "a", "b")
	r.Candidates[0].Roles = []bench.Role{bench.RoleOrchestrator}
	r.Roles = append([]bench.RoleResult{{Role: bench.RoleOrchestrator, Scenarios: []bench.ScenarioResult{{ID: "investigate-migration"}}}}, r.Roles...)
	n := bench.Narrow(r, []string{"b"})
	gt.A(t, n.Roles).Length(1).Required()
	gt.V(t, n.Roles[0].Role).Equal(bench.RoleWorker)
}

func TestForHistoryDropsTracesAndRedactsOnlyErrors(t *testing.T) {
	r := measured("r", 1, "gemini")
	r.Traces = []bench.TraceFile{{Path: "traces/x"}}
	r.Roles[0].Scenarios[0].Trials[0].Error = "denied in gemini"
	r.Roles[0].Scenarios = append(r.Roles[0].Scenarios, bench.ScenarioResult{ID: "sql-named", Failure: "gemini cannot load"})
	redact := func(s string) string { return strings.ReplaceAll(s, "gemini", "<P>") }
	kept := bench.ForHistory(r, redact)
	gt.A(t, kept.Traces).Length(0)
	tr := kept.Roles[0].Scenarios[0].Trials[0]
	gt.S(t, tr.Trace).Equal("")
	gt.S(t, tr.Error).Equal("denied in <P>")
	gt.S(t, kept.Roles[0].Scenarios[1].Failure).Equal("<P> cannot load")
	// What identifies a candidate is not an error, and is kept as it is.
	gt.S(t, tr.Candidate).Equal("gemini")
	gt.V(t, []string{kept.Candidates[0].Name, kept.Candidates[0].Provider, kept.Candidates[0].Model}).
		Equal([]string{"gemini", "gemini", "gemini-3.8-flash"})
	// r itself is unchanged.
	gt.S(t, r.Roles[0].Scenarios[0].Trials[0].Trace).Equal("traces/worker/api-named/gemini/1")
	gt.S(t, r.Roles[0].Scenarios[0].Trials[0].Error).Equal("denied in gemini")
}

func TestReadHistoryReadsEveryResultFile(t *testing.T) {
	dir := t.TempDir()
	for _, r := range []*bench.Result{measured("b-run", 2, "b"), measured("a-run", 1, "a")} {
		gt.NoError(t, bench.WriteResult(bench.HistoryPath(dir, r), r)).Required()
	}
	gt.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a result"), 0o600)).Required()
	sources, err := bench.ReadHistory(dir)
	gt.NoError(t, err).Required()
	gt.A(t, sources).Length(2).Required()
	gt.S(t, sources[0].Result.RunID).Equal("a-run")
	gt.S(t, sources[0].Dir).Equal(dir)

	_, err = bench.ReadHistory(filepath.Join(dir, "missing"))
	gt.Error(t, err)
}
