package report_test

import (
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/report"
)

func overlaps(a, b report.Box) bool {
	return a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H
}

// Five candidates of close scores: no name overlaps another name or a point, and every name stays
// inside the plot.
func TestNamesOfCloseCandidatesDoNotOverlap(t *testing.T) {
	points := []report.Point{{800, 120}, {806, 126}, {812, 118}, {796, 130}, {808, 132}}
	names := []string{"gemini-3.8-flash", "claude-sonnet-5-5", "claude-opus-5-5", "gemini-3.5-flash", "claude-haiku-4-5"}
	labels := report.PlaceLabels(points, names)
	gt.A(t, labels).Length(len(points)).Required()
	for i, l := range labels {
		gt.B(t, l.Box.X >= 72 && l.Box.Y >= 28 && l.Box.X+l.Box.W <= 928 && l.Box.Y+l.Box.H <= 620).True()
		for j, p := range points {
			gt.B(t, overlaps(l.Box, report.Box{X: p.X - 9, Y: p.Y - 9, W: 18, H: 18})).False()
			if j != i {
				gt.B(t, overlaps(l.Box, labels[j].Box)).False()
			}
		}
		gt.N(t, l.PointX).Equal(points[i].X)
	}
}

func TestANameBesideItsPointNeedsNoLeader(t *testing.T) {
	labels := report.PlaceLabels([]report.Point{{300, 300}}, []string{"a"})
	gt.B(t, labels[0].Leader).False()
}

// measuredAt is a measured score of the given mean cost and cost interval, in nano-dollars.
func measuredAt(mean int64, low, high float64) report.RoleScore {
	return report.RoleScore{Candidate: "x", Measured: true, MeanCostNanoUSD: mean, CostCI: report.Interval{Low: low, High: high}}
}

// The axis spans the powers of ten around every measured cost and interval, cheaper to the right.
func TestTheCostAxisHoldsEveryMeasuredCost(t *testing.T) {
	axis := report.NewCostAxis([]report.RoleScore{
		measuredAt(8e5, 6e5, 1e6), measuredAt(8.31e7, 7.5e7, 9e7), {Candidate: "unmeasured", MeanCostNanoUSD: 1e12},
	})
	gt.V(t, axis).Equal(report.CostAxis{Low: 5, High: 8})
	near(t, report.CostAxisX(axis, 1e8), 72)
	near(t, report.CostAxisX(axis, 1e5), 928)
	gt.A(t, report.CostAxisTicks(axis)).Equal([]string{"$0.1", "$0.01", "$0.001", "$0.0001"})
	// Outside the axis, a cost is drawn at the nearer end.
	near(t, report.CostAxisX(axis, 1e9), 72)
	near(t, report.CostAxisX(axis, 1e3), 928)
}

// Two candidates both well under a cent per trial, $0.0007 and $0.0018, are drawn apart.
func TestCandidatesUnderACentAreDrawnApart(t *testing.T) {
	axis := report.NewCostAxis([]report.RoleScore{measuredAt(7e5, 6e5, 8e5), measuredAt(8.31e7, 7.5e7, 9e7)})
	gt.B(t, report.CostAxisX(axis, 7e5)-report.CostAxisX(axis, 1.8e6) > 18).True()
}

func TestANarrowCostAxisMarksTwiceAndFiveTimes(t *testing.T) {
	axis := report.NewCostAxis([]report.RoleScore{measuredAt(2.5e7, 2e7, 3e7)})
	gt.V(t, axis).Equal(report.CostAxis{Low: 7, High: 8})
	gt.A(t, report.CostAxisTicks(axis)).Equal([]string{"$0.1", "$0.05", "$0.02", "$0.01"})
}

func TestACostAxisOfOneValueSpansOnePower(t *testing.T) {
	gt.V(t, report.NewCostAxis([]report.RoleScore{measuredAt(1e7, 1e7, 1e7)})).Equal(report.CostAxis{Low: 7, High: 8})
}

func TestAFreeTrialIsDrawnAtOneNanoDollar(t *testing.T) {
	axis := report.NewCostAxis([]report.RoleScore{measuredAt(0, 0, 0), measuredAt(1e7, 1e7, 1e7)})
	gt.N(t, axis.Low).Equal(0)
	near(t, report.CostAxisX(axis, 0), report.CostAxisX(axis, 1))
}

func TestTheCostAxisOfAChartWithNothingMeasured(t *testing.T) {
	gt.V(t, report.NewCostAxis(nil)).Equal(report.CostAxis{Low: 6, High: 9})
	gt.A(t, report.CostAxisTicks(report.NewCostAxis(nil))).Equal([]string{"$1", "$0.1", "$0.01", "$0.001"})
}
