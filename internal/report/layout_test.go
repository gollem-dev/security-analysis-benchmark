package report_test

import (
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/report"
)

func overlaps(a, b report.Box) bool {
	return a.X < b.X+b.W && b.X < a.X+a.W && a.Y < b.Y+b.H && b.Y < a.Y+a.H
}

// Five candidates of close scores: no name overlaps another name, a point or the zone's label, and
// every name stays inside the plot.
func TestNamesOfCloseCandidatesDoNotOverlap(t *testing.T) {
	points := []report.Point{{800, 120}, {806, 126}, {812, 118}, {796, 130}, {808, 132}}
	names := []string{"gemini-3.8-flash", "claude-sonnet-5-5", "claude-opus-5-5", "gemini-3.5-flash", "claude-haiku-4-5"}
	labels := report.PlaceLabels(points, names)
	gt.A(t, labels).Length(len(points)).Required()
	zone := report.Box{X: 928 - 8 - 8.6*22, Y: 34, W: 8.6 * 22, H: 18}
	for i, l := range labels {
		gt.B(t, l.Box.X >= 72 && l.Box.Y >= 28 && l.Box.X+l.Box.W <= 928 && l.Box.Y+l.Box.H <= 620).True()
		gt.B(t, overlaps(l.Box, zone)).False()
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
