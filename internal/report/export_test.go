package report

type CostAxis = costAxis // compared by its Low and High fields

func NewCostAxis(scores []RoleScore) CostAxis    { return newCostAxis(scores) }
func CostAxisX(a CostAxis, nano float64) float64 { return a.x(nano) }

// CostAxisTicks is the labels of the axis's ticks, from its left end to its right.
func CostAxisTicks(a CostAxis) []string {
	var out []string
	for _, v := range a.ticks() {
		out = append(out, tickLabel(v))
	}
	return out
}
