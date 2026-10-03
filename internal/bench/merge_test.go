package bench_test

import (
	"path/filepath"
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
)

func runResult(id string, version int, violation bool) *bench.Result {
	r := &bench.Result{FormatVersion: bench.FormatVersion, RunID: id, Commit: "c-" + id, SpentNanoUSD: 10,
		Runs:       []bench.RunManifest{{RunID: id}},
		Forecast:   []bench.ForecastLine{{Candidate: "flash", Scenario: "api-named"}},
		Candidates: []bench.Candidate{{Name: "flash", Roles: []bench.Role{bench.RoleWorker}}},
		Roles: []bench.RoleResult{{Role: bench.RoleWorker, Scenarios: []bench.ScenarioResult{
			{ID: "api-named", Kind: bench.KindAPI, Version: 1, Hash: "h",
				Trials:  []bench.TrialResult{{Candidate: "flash", Trial: 1, Trace: "traces/worker/api-named/flash/1"}},
				Tallies: []bench.CandidateTally{{Candidate: "flash", Trials: 1}}},
			{ID: "sql-named", Kind: bench.KindSQL, Version: version,
				Trials:  []bench.TrialResult{{Candidate: "flash", Trial: 1}},
				Tallies: []bench.CandidateTally{{Candidate: "flash", Trials: 1}}},
		}}}}
	if violation {
		r.BudgetViolation = &bench.BudgetViolation{ActualNanoUSD: 2, ReservedNanoUSD: 1}
	}
	return r
}

func TestMergingKeepsTheSameScenariosAndLeavesOutTheChangedOnes(t *testing.T) {
	base := t.TempDir()
	out := filepath.Join(base, "report")
	merged, err := bench.Merge([]bench.Source{
		{Result: runResult("a", 1, false), Dir: filepath.Join(base, "a")},
		{Result: runResult("b", 2, true), Dir: filepath.Join(base, "b")},
	}, out)
	gt.NoError(t, err).Required()

	gt.S(t, merged.RunID).Equal("a")
	gt.S(t, merged.Commit).Equal("c-a")
	gt.A(t, merged.Roles).Length(1).Required()
	gt.A(t, merged.Roles[0].Scenarios).Length(1).Required()
	s := merged.Roles[0].Scenarios[0]
	gt.S(t, s.ID).Equal("api-named")
	gt.A(t, s.Trials).Length(2).Required()
	gt.S(t, s.Trials[0].Candidate).Equal("flash@a")
	gt.S(t, s.Trials[1].Candidate).Equal("flash@b")
	gt.S(t, s.Trials[0].Trace).Equal("../a/traces/worker/api-named/flash/1")
	gt.S(t, s.Trials[1].Trace).Equal("../b/traces/worker/api-named/flash/1")
	gt.A(t, merged.Excluded).Length(1).Required()
	gt.V(t, merged.Excluded[0]).Equal(bench.ExcludedScenario{Role: bench.RoleWorker, Scenario: "sql-named",
		Reason: "the scenario's content differs between runs (version 1 and 2)"})
	gt.A(t, merged.Candidates).Length(2).Required()
	gt.S(t, merged.Candidates[1].Name).Equal("flash@b")
	gt.S(t, merged.Candidates[1].RunID).Equal("b")
	gt.A(t, merged.Forecast).Length(2)
	gt.N(t, merged.SpentNanoUSD).Equal(int64(20))
	gt.V(t, merged.BudgetViolation).NotNil()
	gt.A(t, merged.Runs).Length(2)
}

func TestMergingOneResultKeepsItsNames(t *testing.T) {
	dir := t.TempDir()
	merged, err := bench.Merge([]bench.Source{{Result: runResult("a", 1, false), Dir: dir}}, dir)
	gt.NoError(t, err).Required()
	gt.S(t, merged.Candidates[0].Name).Equal("flash")
	gt.S(t, merged.Roles[0].Scenarios[0].Trials[0].Trace).Equal("traces/worker/api-named/flash/1")
	gt.A(t, merged.Excluded).Length(0)
}
