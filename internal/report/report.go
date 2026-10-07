package report

import (
	"cmp"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

//go:embed report.html.tmpl
var pageSource string

var page = template.Must(template.New("report").Parse(pageSource))

// palette is the candidates' colours in order, as classes: html/template replaces a CSS variable in
// a style attribute with a placeholder, so a colour cannot be given there.
var palette = []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"}

var endLabels = []struct {
	end   bench.End
	label string
}{
	{bench.EndFinalTool, "completed"}, {bench.EndReply, "replied without a tool"}, {bench.EndCap, "stopped at the trial cap"},
	{bench.EndRunCap, "stopped at the run cap"}, {bench.EndError, "provider error"},
}

// Render writes the report of r.
func Render(w io.Writer, r *bench.Result) error {
	if err := page.Execute(w, build(r)); err != nil {
		return goerr.Wrap(err, "failed to render the report", goerr.V("run_id", r.RunID))
	}
	return nil
}

// Chart is one role's chart of quality against mean cost, as an SVG document.
type Chart struct {
	Role string
	SVG  []byte
}

// Charts renders each role's chart of r as an SVG document, in the order the page shows them.
func Charts(r *bench.Result) ([]Chart, error) {
	var charts []Chart
	for _, cv := range build(r).Charts {
		cv.Standalone = true
		var b strings.Builder
		if err := page.ExecuteTemplate(&b, "chart", cv); err != nil {
			return nil, goerr.Wrap(err, "failed to render a chart", goerr.V("run_id", r.RunID), goerr.V("role", cv.Label))
		}
		charts = append(charts, Chart{Role: cv.Label, SVG: []byte(b.String())})
	}
	return charts, nil
}

type pageData struct {
	RunID, Commit, Started, Spent, Max string
	Violation                          string
	Runs                               []runRow
	Charts                             []chartView
	Candidates                         []candidateRow
	Roles                              []roleSection
	NotRun                             int
	Excluded                           []string
}

type runRow struct{ Run, Commit, Started, Go, Gollem, Agentkit, BigQuery, Sampling string }

type candidateRow struct{ Name, Color, Provider, Model, Run, TrialCap, Spent, Baseline string }

type tick struct{ At, Label string }

type chartView struct {
	Label string
	// Standalone makes the chart a document of its own, carrying the styles the page otherwise gives it.
	Standalone               bool
	Width, Height            int
	Left, Right, Top, Bottom string
	MidX, MidY, XTitleY      string
	XTicks, YTicks           []tick
	Points                   []pointView
	Frontier                 string
	Compared                 string
	Rows                     []roleRow
}

type pointView struct {
	Name, Color, Title               string
	X, Y, LabelX, LabelY             string
	Leader                           bool
	LeaderX, LeaderY                 string
	QLow, QHigh, CostLeft, CostRight string
}

type roleRow struct {
	Name, Color                                                string
	Baseline                                                   bool
	Quality, MeanCost, Grounded, PassK, ReachConduct, MeanTime string
	Gap, Unmeasured                                            string
	Difficulties                                               string
}

type roleSection struct {
	Label string
	Kinds []kindSection
}

type kindSection struct {
	Label     string
	Scenarios []scenarioView
}

type scenarioView struct {
	Heading, Saturation, Failure string
	Rows                         []scenarioRow
}

type scenarioRow struct {
	Name, Color, Grounded, PassK, Quality, MeanCost, MeanTime, Calls, Actions, Lost, Endings, NotRun string
}

func coord(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// whole is a score rounded to a whole number, with ASCII signs and no negative zero.
func whole(v float64) string {
	r := math.Round(v)
	if r == 0 {
		return "0"
	}
	return strconv.FormatFloat(r, 'f', 0, 64)
}

func percent(v float64) string { return whole(100*v) + "%" }

func shortCommit(c string) string { return c[:min(7, len(c))] }

func maxText(raw string) string {
	if n, err := pricing.ParseUSD(raw); err == nil {
		return n.USD()
	}
	return raw
}

func build(r *bench.Result) pageData {
	d := pageData{RunID: r.RunID, Commit: shortCommit(r.Commit), Started: r.StartedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Spent: pricing.NanoUSD(r.SpentNanoUSD).USD(), Max: maxText(r.MaxUSD)}
	if v := r.BudgetViolation; v != nil {
		d.Violation = fmt.Sprintf("An LLM call cost %s, more than the %s reserved for it before the call. The run stopped there, "+
			"because the spending limit could no longer be guaranteed.",
			pricing.NanoUSD(v.ActualNanoUSD).USD4(), pricing.NanoUSD(v.ReservedNanoUSD).USD4())
	}
	for _, m := range r.Runs {
		sampling := m.Sampling
		if sampling == bench.SamplingProviderDefault {
			sampling = "Provider defaults"
		}
		d.Runs = append(d.Runs, runRow{Run: m.RunID, Commit: shortCommit(m.Commit), Started: m.StartedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Go: m.GoVersion, Gollem: m.Modules["github.com/gollem-dev/gollem"], Agentkit: m.Modules["github.com/gollem-dev/agentkit"],
			BigQuery: m.Modules["cloud.google.com/go/bigquery"], Sampling: sampling})
	}
	color := map[string]string{}
	for i, c := range r.Candidates {
		color[c.Name] = palette[i%len(palette)]
		var baseline []string
		for _, role := range c.Current {
			baseline = append(baseline, string(role))
		}
		d.Candidates = append(d.Candidates, candidateRow{Name: c.Name, Color: color[c.Name], Provider: c.Provider, Model: c.Model,
			Run: cmp.Or(c.RunID, r.RunID), TrialCap: r.PlanOf(c.Name).TrialCapUSD.USD(), Spent: pricing.NanoUSD(c.CostNanoUSD).USD4(), Baseline: strings.Join(baseline, ", ")})
	}
	for _, view := range Roles(r) {
		d.Charts = append(d.Charts, chart(r, view, color))
	}
	for _, rr := range r.Roles {
		section := roleSection{Label: string(rr.Role)}
		for _, kind := range bench.Kinds {
			ks := kindSection{Label: kind.Label()}
			for _, s := range rr.Scenarios {
				if s.Kind != kind {
					continue
				}
				sv, notRun := scenarioSection(r, s, color)
				d.NotRun += notRun
				ks.Scenarios = append(ks.Scenarios, sv)
			}
			if len(ks.Scenarios) > 0 {
				section.Kinds = append(section.Kinds, ks)
			}
		}
		d.Roles = append(d.Roles, section)
	}
	for _, e := range r.Excluded {
		d.Excluded = append(d.Excluded, fmt.Sprintf("%s / %s: %s", e.Role, e.Scenario, e.Reason))
	}
	return d
}

func isBaseline(r *bench.Result, name string, role bench.Role) bool {
	for _, c := range r.Candidates {
		if c.Name == name {
			return slices.Contains(c.Current, role)
		}
	}
	return false
}

func chart(r *bench.Result, view RoleView, color map[string]string) chartView {
	cv := chartView{Label: string(view.Role), Width: chartWidth, Height: chartHeight,
		Left: coord(plotLeft), Right: coord(plotRight), Top: coord(plotTop), Bottom: coord(plotBottom),
		MidX: coord((plotLeft + plotRight) / 2), MidY: coord((plotTop + plotBottom) / 2), XTitleY: coord(plotBottom + 48),
		Compared: fmt.Sprintf("Scenarios compared: %d of the role's %d", view.Compared, view.Total)}
	axis := newCostAxis(view.Scores)
	for _, v := range axis.ticks() {
		cv.XTicks = append(cv.XTicks, tick{At: coord(axis.x(v)), Label: tickLabel(v)})
	}
	for v := 0.0; v <= 100; v += 25 {
		cv.YTicks = append(cv.YTicks, tick{At: coord(chartY(v)), Label: whole(v)})
	}
	difficulties := map[int]bool{}
	for _, s := range roleScenarios(r, view.Role) {
		difficulties[s.Difficulty] = true
	}
	var points []Point
	var names []string
	var measured []RoleScore
	for _, sc := range view.Scores {
		row := roleRow{Name: sc.Candidate, Color: color[sc.Candidate], Baseline: isBaseline(r, sc.Candidate, view.Role),
			Unmeasured: strconv.Itoa(sc.Unmeasured)}
		if !sc.Measured {
			row.Quality, row.Grounded, row.PassK = "not measured", "not measured", "not measured"
			row.ReachConduct, row.MeanCost, row.MeanTime = "-", "-", "-"
			cv.Rows = append(cv.Rows, row)
			continue
		}
		row.Quality = fmt.Sprintf("%s [%s, %s]", whole(sc.Quality), whole(sc.QualityCI.Low), whole(sc.QualityCI.High))
		row.MeanCost = fmt.Sprintf("%s [%s, %s]", pricing.NanoUSD(sc.MeanCostNanoUSD).USD2Sig(),
			pricing.NanoUSD(math.Round(sc.CostCI.Low)).USD2Sig(), pricing.NanoUSD(math.Round(sc.CostCI.High)).USD2Sig())
		row.Grounded = fmt.Sprintf("%s [%s, %s] (%d / %d)", percent(sc.GroundedRate), percent(sc.GroundedCI.Low),
			percent(sc.GroundedCI.High), sc.Grounded, sc.Trials)
		row.PassK = "not measured"
		if sc.PassKMeasured {
			row.PassK = percent(sc.PassK)
		}
		row.ReachConduct = fmt.Sprintf("%.2f / %.2f", sc.ReachMean, sc.ConductMean)
		row.MeanTime = fmt.Sprintf("%.1f s", sc.MeanSeconds)
		switch {
		case sc.Candidate == view.Best:
			row.Gap = "best"
		case sc.Diff != nil:
			verdict := "not distinguishable"
			if sc.Diff.Distinguishable {
				verdict = "distinguishable"
			}
			row.Gap = fmt.Sprintf("%s [%s, %s] %s", whole(sc.Diff.Quality), whole(sc.Diff.CI.Low), whole(sc.Diff.CI.High), verdict)
		}
		var lines []string
		for dd := 1; dd <= bench.MaxDifficulty; dd++ {
			if !difficulties[dd] {
				continue
			}
			if ds := sc.ByDifficulty[dd-1]; ds.Measured {
				lines = append(lines, fmt.Sprintf("Difficulty %d: quality %s, mean cost %s", dd, whole(ds.Quality),
					pricing.NanoUSD(ds.MeanCostNanoUSD).USD2Sig()))
			} else {
				lines = append(lines, fmt.Sprintf("Difficulty %d: not measured", dd))
			}
		}
		row.Difficulties = strings.Join(lines, " / ")
		cv.Rows = append(cv.Rows, row)
		measured = append(measured, sc)
		points = append(points, Point{X: axis.x(float64(sc.MeanCostNanoUSD)), Y: chartY(sc.Quality)})
		names = append(names, sc.Candidate)
	}
	labels := PlaceLabels(points, names)
	for k, sc := range measured {
		l := labels[k]
		cv.Points = append(cv.Points, pointView{Name: sc.Candidate, Color: color[sc.Candidate],
			Title: sc.Candidate + "\n" + cv.Rows[slices.IndexFunc(cv.Rows, func(rr roleRow) bool { return rr.Name == sc.Candidate })].Difficulties,
			X:     coord(points[k].X), Y: coord(points[k].Y), LabelX: coord(l.X), LabelY: coord(l.Y),
			Leader: l.Leader, LeaderX: coord(l.LeaderX), LeaderY: coord(l.LeaderY),
			QLow: coord(chartY(sc.QualityCI.Low)), QHigh: coord(chartY(sc.QualityCI.High)),
			CostLeft: coord(axis.x(sc.CostCI.High)), CostRight: coord(axis.x(sc.CostCI.Low))})
	}
	if frontier := Pareto(view.Scores); frontier != nil {
		var xy []string
		for _, i := range frontier {
			sc := view.Scores[i]
			xy = append(xy, coord(axis.x(float64(sc.MeanCostNanoUSD)))+","+coord(chartY(sc.Quality)))
		}
		cv.Frontier = strings.Join(xy, " ")
	}
	return cv
}

func scenarioSection(r *bench.Result, s bench.ScenarioResult, color map[string]string) (scenarioView, int) {
	sv := scenarioView{Failure: s.Failure}
	if s.MinRounds > 0 {
		sv.Heading = fmt.Sprintf("%s (difficulty %d, fewest rounds %d, estimated LLM calls %d)", s.ID, s.Difficulty, s.MinRounds, s.ExpectedCalls)
	} else {
		sv.Heading = fmt.Sprintf("%s (difficulty %d, fewest actions %d, estimated LLM calls %d)", s.ID, s.Difficulty, s.MinActions, s.ExpectedCalls)
	}
	switch ScenarioSaturation(s) {
	case SaturationCeiling:
		sv.Saturation = "Ceiling: every candidate measured reached a grounded conclusion in every trial, so this scenario does not tell the candidates apart."
	case SaturationFloor:
		sv.Saturation = "Floor: no candidate reached a grounded conclusion. Before doubting the candidates, check the scenario and its grader for errors."
	}
	notRun := 0
	for _, c := range r.Candidates {
		t, ok := s.Tally(c.Name)
		if !ok {
			continue
		}
		smp := collect(s, c.Name)
		row := scenarioRow{Name: c.Name, Color: color[c.Name], Grounded: fmt.Sprintf("%d / %d", t.Grounded, t.Trials),
			PassK: "-", Quality: "-", MeanCost: "-", MeanTime: "-", Calls: "-", Actions: "-",
			Lost: shortfalls(s.Trials, c.Name), Endings: endings(s.Trials, c.Name), NotRun: strconv.Itoa(t.NotRun)}
		if p, ok := PassHatK(t.Trials, t.Grounded, ReliabilityK); ok {
			row.PassK = percent(p)
		}
		if cost, ok := t.MeanCost(); ok {
			row.Quality = whole(average(smp.quality))
			row.MeanCost = pricing.NanoUSD(cost).USD2Sig()
			row.MeanTime = fmt.Sprintf("%.1f s", average(smp.seconds))
			row.Calls = fmt.Sprintf("%.1f", t.MeanCalls())
			row.Actions = actions(s.Trials, c.Name)
		}
		notRun += t.NotRun
		sv.Rows = append(sv.Rows, row)
	}
	return sv, notRun
}

// actions is how the candidate's counted trials went about their work, on average.
func actions(trials []bench.TrialResult, candidate string) string {
	var n, acts, explore, failed, dup, detour, rounds int
	byRounds := false
	for _, t := range trials {
		if t.Candidate != candidate || !t.End.Counted() {
			continue
		}
		n++
		byRounds = byRounds || t.Conduct.MinRounds > 0
		rounds += t.Conduct.Rounds
		acts += t.Conduct.Actions
		explore += t.Conduct.Explore
		failed += t.Conduct.Failed
		dup += t.Conduct.Duplicate
		detour += t.Conduct.Detour
	}
	if n == 0 {
		return "-"
	}
	avg := func(v int) string { return fmt.Sprintf("%.1f", float64(v)/float64(n)) }
	if byRounds {
		return fmt.Sprintf("%s rounds, %s actions (explore %s, failed %s, duplicate %s, empty %s)",
			avg(rounds), avg(acts), avg(explore), avg(failed), avg(dup), avg(detour))
	}
	return fmt.Sprintf("%s (explore %s, failed %s, duplicate %s, detour %s)", avg(acts), avg(explore), avg(failed), avg(dup), avg(detour))
}

// shortfalls counts, over the candidate's counted trials, what kept each from a grounded conclusion.
// The last four are counted only among trials whose conclusion was right.
func shortfalls(trials []bench.TrialResult, candidate string) string {
	var none, wrong, fabricated, missing, unsupporting, speculation int
	for _, t := range trials {
		if t.Candidate != candidate || !t.End.Counted() {
			continue
		}
		r := t.Reach
		switch {
		case t.End != bench.EndFinalTool:
			none++
			continue
		case !r.Concluded:
			wrong++
			continue
		}
		if r.Fabricated {
			fabricated++
		}
		if r.SupportMissing > 0 {
			missing++
		}
		if r.Unsupporting > 0 {
			unsupporting++
		}
		if r.Speculation > 0 {
			speculation++
		}
	}
	var parts []string
	for _, p := range []struct {
		label string
		n     int
	}{{"no conclusion", none}, {"wrong conclusion", wrong}, {"fabricated evidence", fabricated}, {"missing evidence", missing},
		{"unsupporting record cited", unsupporting}, {"speculation", speculation}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%s (%d)", p.label, p.n))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// endings counts how the candidate's trials ended.
func endings(trials []bench.TrialResult, candidate string) string {
	counts := map[bench.End]int{}
	for _, t := range trials {
		if t.Candidate == candidate {
			counts[t.End]++
		}
	}
	var parts []string
	for _, e := range endLabels {
		if n := counts[e.end]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", e.label, n))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
