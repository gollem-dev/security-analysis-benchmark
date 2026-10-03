package report

import (
	"math"
	"slices"
	"sort"
)

// The chart's frame in its SVG's coordinates: the drawing and its plot area.
const (
	chartWidth, chartHeight                      = 960, 680
	plotLeft, plotRight, plotTop, plotBottom     = 72.0, 928.0, 28.0, 620.0
	labelHeight, labelPad, pointRadius, charWide = 18.0, 4.0, 9.0, 8.6
)

// zoneLabel is the text in the chart's top-right quarter.
const zoneLabel = "Low cost, high quality"

// chartX and chartY place a score on the chart.
func chartX(v float64) float64 { return plotLeft + (plotRight-plotLeft)*v/100 }
func chartY(v float64) float64 { return plotBottom - (plotBottom-plotTop)*v/100 }

// Point is a candidate's place on the chart.
type Point struct{ X, Y float64 }

// Label is where a candidate's name is drawn: X and Y are where its text starts and its baseline,
// Box the area it covers. Leader is set when the name had to move away from its point, and runs
// from the point at PointX, PointY to the name's nearest edge at LeaderX, LeaderY.
type Label struct {
	X, Y, PointX, PointY float64
	Leader               bool
	LeaderX, LeaderY     float64
	Box                  Box
}

// Box is a rectangle on the chart.
type Box struct{ X, Y, W, H float64 }

func (b Box) overlaps(o Box) bool {
	return b.X < o.X+o.W && o.X < b.X+b.W && b.Y < o.Y+o.H && o.Y < b.Y+b.H
}

// textWidth estimates how wide s is drawn at the chart's 15px.
func textWidth(s string) float64 { return charWide * float64(len([]rune(s))) }

// zoneLabelBox is the area the zone's own label covers.
func zoneLabelBox() Box {
	w := textWidth(zoneLabel)
	return Box{X: plotRight - 8 - w, Y: plotTop + 6, W: w, H: labelHeight}
}

// PlaceLabels puts every point's name where it overlaps no other name, no point and the zone's
// label, and stays inside the plot: beside its point when it can, further out along a leader line
// when it cannot. Points are placed from the top, so the same scores always lay out the same way.
func PlaceLabels(points []Point, names []string) []Label {
	taken := []Box{zoneLabelBox()}
	for _, p := range points {
		taken = append(taken, Box{X: p.X - pointRadius, Y: p.Y - pointRadius, W: 2 * pointRadius, H: 2 * pointRadius})
	}
	order := make([]int, len(points))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return points[order[a]].Y < points[order[b]].Y })
	plot := Box{X: plotLeft, Y: plotTop, W: plotRight - plotLeft, H: plotBottom - plotTop}
	inside := func(b Box) bool {
		return b.X >= plot.X && b.Y >= plot.Y && b.X+b.W <= plot.X+plot.W && b.Y+b.H <= plot.Y+plot.H
	}
	out := make([]Label, len(points))
	for _, i := range order {
		p := points[i]
		w, h := textWidth(names[i])+2*labelPad, labelHeight
		var chosen Box
		found := false
		// Right, left, above and below at each distance, then the diagonals, the closest first.
		for _, d := range []float64{13, 28, 48, 72, 100, 135} {
			for _, at := range []Box{
				{X: p.X + d, Y: p.Y - h/2}, {X: p.X - d - w, Y: p.Y - h/2},
				{X: p.X - w/2, Y: p.Y - d - h}, {X: p.X - w/2, Y: p.Y + d},
				{X: p.X + d, Y: p.Y - d - h}, {X: p.X - d - w, Y: p.Y - d - h},
				{X: p.X + d, Y: p.Y + d}, {X: p.X - d - w, Y: p.Y + d},
			} {
				b := Box{X: at.X, Y: at.Y, W: w, H: h}
				if inside(b) && !slices.ContainsFunc(taken, b.overlaps) {
					chosen, found = b, true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			chosen = Box{X: min(p.X+pointRadius+4, plot.X+plot.W-w), Y: p.Y - h/2, W: w, H: h}
		}
		taken = append(taken, chosen)
		l := Label{X: chosen.X + labelPad, Y: chosen.Y + h - labelPad, PointX: p.X, PointY: p.Y, Box: chosen}
		// A name further from its point than the point's own size needs a line to say whose it is.
		nx, ny := max(chosen.X, min(p.X, chosen.X+w)), max(chosen.Y, min(p.Y, chosen.Y+h))
		if math.Hypot(nx-p.X, ny-p.Y) > pointRadius+6 {
			l.Leader, l.LeaderX, l.LeaderY = true, nx, ny
		}
		out[i] = l
	}
	return out
}
