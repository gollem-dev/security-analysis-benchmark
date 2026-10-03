package report_test

import (
	"math"
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/report"
)

func near(t *testing.T, got, want float64) {
	t.Helper()
	gt.B(t, math.Abs(got-want) < 1e-9).True()
}

func TestReachFactor(t *testing.T) {
	near(t, report.ReachFactor(bench.Reach{Concluded: false}), 0)
	near(t, report.ReachFactor(bench.Reach{Concluded: true, Fabricated: true}), 0)
	near(t, report.ReachFactor(bench.Reach{Concluded: true, SupportOf: 2, SupportMissing: 1}), 0.75)
	near(t, report.ReachFactor(bench.Reach{Concluded: true, SupportOf: 2, Unsupporting: 1}), 0.75)
	near(t, report.ReachFactor(bench.Reach{Concluded: true, SupportOf: 2, Speculation: 1}), 0.75)
}

func TestConductFactor(t *testing.T) {
	// A worker: explore left out, fewest over the calls, failed, duplicate and half of detour.
	w := bench.Conduct{Actions: 6, Explore: 2, Minimal: 2, Failed: 1, Detour: 1}
	near(t, report.ConductFactor(w), (2.0/4)*(1-1.0/4)*(1-0)*(1-0.5*1/4))
	// An orchestrator: rounds over the fewest, and no detour penalty.
	o := bench.Conduct{Actions: 6, Explore: 1, MinRounds: 3, Rounds: 4, Detour: 2, Duplicate: 1}
	near(t, report.ConductFactor(o), (3.0/4)*(1-0)*(1-1.0/5))
	near(t, report.ConductFactor(bench.Conduct{Actions: 2, Explore: 2, Minimal: 1}), 0)
}

func TestEfficiency(t *testing.T) {
	cap := bench.DefaultPlan.TrialCapUSD
	near(t, report.Efficiency(10_000_000, cap), 100)
	near(t, report.Efficiency(int64(cap), cap), 0)
	near(t, report.Efficiency(20_000_000, cap), 100*math.Log(2e9/2e7)/math.Log(2e9/1e7))
	gt.N(t, report.HalvingGain(cap)).Equal(13)
}

func TestPassHatK(t *testing.T) {
	p, ok := report.PassHatK(6, 6, 3)
	gt.B(t, ok).True()
	near(t, p, 1)
	p, _ = report.PassHatK(6, 3, 3)
	near(t, p, 1.0/20)
	p, _ = report.PassHatK(6, 2, 3)
	near(t, p, 0)
	p, _ = report.PassHatK(6, 5, 3)
	near(t, p, 0.5)
	_, ok = report.PassHatK(2, 2, 3)
	gt.B(t, ok).False()
}

// trial is a counted trial of quality 100 when grounded, and a reply with no conclusion otherwise.
func trial(candidate string, n int, grounded bool, cost int64) bench.TrialResult {
	t := bench.TrialResult{Candidate: candidate, Trial: n, End: bench.EndReply, CostNanoUSD: cost, Seconds: 10,
		Grade: bench.Grade{Conduct: bench.Conduct{Actions: 2, Minimal: 2}}}
	if grounded {
		t.End = bench.EndFinalTool
		t.Reach = bench.Reach{Concluded: true, SupportOf: 1}
	}
	return t
}

func scenarioOf(id string, difficulty int, trials ...bench.TrialResult) bench.ScenarioResult {
	s := bench.ScenarioResult{ID: id, Kind: bench.KindAPI, Difficulty: difficulty, MinActions: 2, Trials: trials}
	tallies := map[string]*bench.CandidateTally{}
	var order []string
	for _, t := range trials {
		if tallies[t.Candidate] == nil {
			tallies[t.Candidate] = &bench.CandidateTally{Candidate: t.Candidate}
			order = append(order, t.Candidate)
		}
		tallies[t.Candidate].Add(t.End, t.Grade, 2, t.CostNanoUSD)
	}
	for _, c := range order {
		s.Tallies = append(s.Tallies, *tallies[c])
	}
	return s
}

func resultOf(names []string, scenarios ...bench.ScenarioResult) *bench.Result {
	r := &bench.Result{FormatVersion: bench.FormatVersion, Plan: bench.DefaultPlan, MaxUSD: "30.00",
		Roles: []bench.RoleResult{{Role: bench.RoleWorker, Scenarios: scenarios}}}
	for _, n := range names {
		r.Candidates = append(r.Candidates, bench.Candidate{Name: n, Roles: []bench.Role{bench.RoleWorker}})
	}
	return r
}

func trials(candidate string, grounded []bool, cost int64) []bench.TrialResult {
	var out []bench.TrialResult
	for i, g := range grounded {
		out = append(out, trial(candidate, i+1, g, cost))
	}
	return out
}

// A candidate measured on fewer scenarios is scored, as every other, only on those every candidate
// was measured on.
func TestScoresRestOnTheScenariosEveryCandidateWasMeasuredOn(t *testing.T) {
	all := []bool{true, true}
	r := resultOf([]string{"a", "b"},
		scenarioOf("s1", 1, append(trials("a", all, 1e7), trials("b", all, 1e7)...)...),
		scenarioOf("s2", 2, append(trials("a", all, 1e7), trials("b", []bool{false, false}, 1e7)...)...),
		scenarioOf("s3", 3, trials("a", []bool{false, false}, 1e7)...),
		scenarioOf("s4", 4, trials("a", []bool{false, false}, 1e7)...),
	)
	view := report.Roles(r)[0]
	gt.N(t, view.Compared).Equal(2)
	gt.N(t, view.Total).Equal(4)
	a, b := view.Scores[0], view.Scores[1]
	near(t, a.Quality, 100)
	near(t, b.Quality, 100*1.0/3)
	gt.N(t, a.Unmeasured).Equal(0)
	gt.N(t, b.Unmeasured).Equal(2)
	gt.N(t, a.Trials).Equal(4)
	gt.S(t, view.Best).Equal("a")
	gt.B(t, a.ByDifficulty[0].Measured && a.ByDifficulty[1].Measured).True()
	gt.B(t, a.ByDifficulty[2].Measured).False()
	near(t, a.MeanSeconds, 10)
}

func TestIntervalsAreFixedAndHoldThePointEstimate(t *testing.T) {
	r := resultOf([]string{"a", "b"},
		scenarioOf("s1", 1, append(trials("a", []bool{true, false, true}, 2e7), trials("b", []bool{true, true, true}, 5e7)...)...),
		scenarioOf("s2", 2, append(trials("a", []bool{false, true, true}, 3e7), trials("b", []bool{true, false, true}, 6e7)...)...),
	)
	first, again := report.Roles(r)[0], report.Roles(r)[0]
	for i, sc := range first.Scores {
		gt.V(t, sc.QualityCI).Equal(again.Scores[i].QualityCI)
		gt.V(t, sc.EfficiencyCI).Equal(again.Scores[i].EfficiencyCI)
		gt.B(t, sc.QualityCI.Contains(sc.Quality)).True()
		gt.B(t, sc.EfficiencyCI.Contains(sc.Efficiency)).True()
		gt.B(t, sc.GroundedCI.Contains(sc.GroundedRate)).True()
		gt.B(t, sc.QualityCI.High > sc.QualityCI.Low).True()
	}
}

func TestAnIntervalOfUnvaryingQualityHasNoWidth(t *testing.T) {
	r := resultOf([]string{"a"},
		scenarioOf("s1", 1, trials("a", []bool{true, true}, 2e7)...),
		scenarioOf("s2", 2, trials("a", []bool{true, true}, 2e7)...))
	sc := report.Roles(r)[0].Scores[0]
	gt.V(t, sc.QualityCI).Equal(report.Interval{Low: 100, High: 100})

	one := resultOf([]string{"a"}, scenarioOf("s1", 1, trials("a", []bool{true}, 3e7)...))
	sc = report.Roles(one)[0].Scores[0]
	gt.V(t, sc.QualityCI).Equal(report.Interval{Low: sc.Quality, High: sc.Quality})
	gt.V(t, sc.EfficiencyCI).Equal(report.Interval{Low: sc.Efficiency, High: sc.Efficiency})
	gt.B(t, sc.PassKMeasured).False()
}

func TestTheGapToTheBest(t *testing.T) {
	same := resultOf([]string{"a", "b"},
		scenarioOf("s1", 1, append(trials("a", []bool{true, true}, 1e7), trials("b", []bool{true, true}, 1e7)...)...))
	view := report.Roles(same)[0]
	// Equal quality: the name first in order is the best.
	gt.S(t, view.Best).Equal("a")
	gt.V(t, view.Scores[0].Diff).Nil()
	d := view.Scores[1].Diff
	gt.V(t, d).NotNil().Required()
	near(t, d.Quality, 0)
	gt.V(t, d.CI).Equal(report.Interval{})
	gt.B(t, d.Distinguishable).False()

	apart := resultOf([]string{"a", "b"},
		scenarioOf("s1", 1, append(trials("a", []bool{true, true, true}, 1e7), trials("b", []bool{false, false, false}, 1e7)...)...),
		scenarioOf("s2", 2, append(trials("a", []bool{true, true, true}, 1e7), trials("b", []bool{false, false, false}, 1e7)...)...))
	view = report.Roles(apart)[0]
	gt.B(t, view.Scores[1].Diff.Distinguishable).True()
	near(t, view.Scores[1].Diff.Quality, -100)
}

func TestPassKOfARole(t *testing.T) {
	r := resultOf([]string{"a"},
		scenarioOf("s1", 1, trials("a", []bool{true, true, true, true, true, true}, 1e7)...),
		scenarioOf("s2", 3, trials("a", []bool{true, true, true, false, false, false}, 1e7)...))
	sc := report.Roles(r)[0].Scores[0]
	gt.B(t, sc.PassKMeasured).True()
	near(t, sc.PassK, (1*1+3*(1.0/20))/4)
}

func TestCeilingAndFloor(t *testing.T) {
	gt.V(t, report.ScenarioSaturation(scenarioOf("s", 1, append(trials("a", []bool{true, true}, 1), trials("b", []bool{true}, 1)...)...))).
		Equal(report.SaturationCeiling)
	gt.V(t, report.ScenarioSaturation(scenarioOf("s", 1, append(trials("a", []bool{false}, 1), trials("b", []bool{false}, 1)...)...))).
		Equal(report.SaturationFloor)
	gt.V(t, report.ScenarioSaturation(scenarioOf("s", 1, append(trials("a", []bool{true}, 1), trials("b", []bool{false}, 1)...)...))).
		Equal(report.SaturationNone)
	gt.V(t, report.ScenarioSaturation(scenarioOf("s", 1, trials("a", []bool{true, true}, 1)...))).Equal(report.SaturationNone)
}

func TestPareto(t *testing.T) {
	scores := []report.RoleScore{
		{Candidate: "a", Measured: true, Quality: 80, Efficiency: 50},
		{Candidate: "b", Measured: true, Quality: 60, Efficiency: 90},
		{Candidate: "c", Measured: true, Quality: 50, Efficiency: 40},
		{Candidate: "d", Measured: false},
	}
	gt.A(t, report.Pareto(scores)).Equal([]int{0, 1})
	gt.V(t, report.Pareto(scores[:1])).Nil()
	gt.V(t, report.Pareto([]report.RoleScore{scores[0], scores[2]})).Nil()
}
