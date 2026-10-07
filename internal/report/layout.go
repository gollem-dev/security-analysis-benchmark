package report

import (
	"math"
	"slices"
	"sort"
	"strconv"
)

// The chart's frame in its SVG's coordinates: the drawing and its plot area.
const (
	chartWidth, chartHeight                      = 960, 680
	plotLeft, plotRight, plotTop, plotBottom     = 72.0, 928.0, 28.0, 620.0
	labelHeight, labelPad, pointRadius, charWide = 18.0, 4.0, 9.0, 8.6
)

// chartY places a quality on the chart.
func chartY(v float64) float64 { return plotBottom - (plotBottom-plotTop)*v/100 }

// costAxis is the cost axis of one chart, on a logarithmic scale: from 10^High nano-dollars at its
// left end to 10^Low at its right, so that the cheaper is further right as the higher is further up.
type costAxis struct{ Low, High int }

// unmeasuredAxis is the axis of a chart with no measured candidate: $0.001 to $1.
var unmeasuredAxis = costAxis{Low: 6, High: 9}

// newCostAxis is the narrowest axis between powers of ten that holds every measured score's mean
// cost and its interval. A cost below one nano-dollar is drawn at one.
func newCostAxis(scores []RoleScore) costAxis {
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, sc := range scores {
		if !sc.Measured {
			continue
		}
		mean := float64(sc.MeanCostNanoUSD)
		lo = min(lo, sc.CostCI.Low, mean)
		hi = max(hi, sc.CostCI.High, mean)
	}
	if math.IsInf(lo, 1) {
		return unmeasuredAxis
	}
	a := costAxis{Low: powerAtOrBelow(max(lo, 1)), High: powerAtOrAbove(max(hi, 1))}
	if a.High == a.Low {
		a.High++
	}
	return a
}

// powerAtOrBelow and powerAtOrAbove are the exponents of the powers of ten nearest v, which is at
// least 1, from below and from above. They compare against exact powers rather than round
// math.Log10, which can land just beside an integer for a power of ten.
func powerAtOrBelow(v float64) int {
	k := 0
	for math.Pow10(k+1) <= v {
		k++
	}
	return k
}

func powerAtOrAbove(v float64) int {
	k := 0
	for math.Pow10(k) < v {
		k++
	}
	return k
}

// x places a cost on the chart; a cost outside the axis is drawn at its nearer end.
func (a costAxis) x(nano float64) float64 {
	v := min(max(math.Log10(max(nano, 1)), float64(a.Low)), float64(a.High))
	return plotLeft + (plotRight-plotLeft)*(float64(a.High)-v)/float64(a.High-a.Low)
}

// ticks are the costs the axis marks, from its left end to its right: every power of ten, and also
// twice and five times each when the axis spans two powers or fewer, so it never has only two marks.
func (a costAxis) ticks() []float64 {
	out := []float64{math.Pow10(a.High)}
	for k := a.High - 1; k >= a.Low; k-- {
		if a.High-a.Low <= 2 {
			out = append(out, 5*math.Pow10(k), 2*math.Pow10(k))
		}
		out = append(out, math.Pow10(k))
	}
	return out
}

// tickLabel is a tick's cost in dollars with no trailing zeros: "$0.01", "$1".
func tickLabel(nano float64) string { return "$" + strconv.FormatFloat(nano/1e9, 'f', -1, 64) }

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

// PlaceLabels puts every point's name where it overlaps no other name and no point, and stays
// inside the plot: beside its point when it can, further out along a leader line when it cannot.
// Points are placed from the top, so the same scores always lay out the same way.
func PlaceLabels(points []Point, names []string) []Label {
	var taken []Box
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
