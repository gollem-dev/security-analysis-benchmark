package pricing_test

import (
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

func TestParseUSD(t *testing.T) {
	for in, want := range map[string]pricing.NanoUSD{
		"30.00":       30_000_000_000,
		"0.000000001": 1,
		"2":           2_000_000_000,
		"0.5":         500_000_000,
	} {
		got, err := pricing.ParseUSD(in)
		gt.NoError(t, err).Required()
		gt.V(t, got).Equal(want)
	}
	for _, in := range []string{"", "-1", "1.0000000001", "1e3", "$1", "1.", ".5", "1,000"} {
		_, err := pricing.ParseUSD(in)
		gt.Error(t, err)
	}
}

func TestCostPricesEveryComponent(t *testing.T) {
	r := pricing.Rate{Input: 1000, Output: 10_000, CacheRead: 100, CacheWrite: 1250}
	gt.V(t, r.Cost(3000, 300, 2000, 500)).Equal(pricing.NanoUSD(500*1000 + 2000*100 + 500*1250 + 300*10_000))
	// A cache larger than the input leaves nothing uncached rather than a negative charge.
	gt.V(t, r.Cost(1000, 0, 2000, 500)).Equal(pricing.NanoUSD(2000*100 + 500*1250))
}

// A cache read on claude-opus-5-5 is 0.05 times its input price, not the 0.1 of the other models.
func TestTheEmbeddedCachePricesOfOpus55(t *testing.T) {
	table, err := pricing.Embedded()
	gt.NoError(t, err).Required()
	r, ok := table.RateOf("claude-opus-5-5")
	gt.B(t, ok).True().Required()
	gt.V(t, r.Cost(10_000, 500, 8_000, 1_000)).Equal(pricing.NanoUSD(1_000*4_000 + 8_000*200 + 1_000*5_000 + 500*20_000))
}

func TestTheEmbeddedTablePricesTheBundledCandidates(t *testing.T) {
	table, err := pricing.Embedded()
	gt.NoError(t, err).Required()
	for _, model := range []string{"gemini-3.8-flash", "claude-sonnet-5-5", "claude-opus-5-5"} {
		r, ok := table.RateOf(model)
		gt.B(t, ok).True()
		gt.B(t, r.Input > 0 && r.Output > 0).True()
	}
	_, ok := table.RateOf("no-such-model")
	gt.B(t, ok).False()
}

func TestATableWithAnUnpricedModelIsRefused(t *testing.T) {
	_, err := pricing.ParseTable([]byte(`{"m": {"input": 0, "output": 10}}`))
	gt.Error(t, err)
	_, err = pricing.ParseTable([]byte(`{"m": {"input": 1, "output": 10}}`))
	gt.NoError(t, err)
}

func TestFormatting(t *testing.T) {
	n := pricing.NanoUSD(1_234_567_890)
	gt.S(t, n.USD()).Equal("$1.23")
	gt.S(t, n.USD4()).Equal("$1.2346")
	gt.S(t, pricing.NanoUSD(9_999_999).USD()).Equal("$0.00")
	gt.S(t, pricing.NanoUSD(0).USD4()).Equal("$0.0000")
	gt.S(t, pricing.NanoUSD(-10_000_000).USD()).Equal("-$0.01")
}
