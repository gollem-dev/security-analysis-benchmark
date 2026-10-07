package bench

import (
	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

// Plan is how a run spends its trials.
type Plan struct {
	// Trials is how many times every candidate runs every scenario of its roles.
	Trials int `json:"trials"`
	// TrialCapUSD is the most one trial may spend.
	TrialCapUSD pricing.NanoUSD `json:"trial_cap_nano_usd"`
	// MaxOutputTokens is the most one LLM call may write, thinking included. It bounds a call's
	// worst case, so it is sent with every call.
	MaxOutputTokens int `json:"max_output_tokens"`
	// Concurrency is how many trials run at once.
	Concurrency int `json:"concurrency"`
}

// DefaultPlan is the plan of a configuration that names none.
var DefaultPlan = Plan{Trials: 6, TrialCapUSD: 2_000_000_000, MaxOutputTokens: 8000, Concurrency: 4}

// Validate refuses a plan that could not run.
func (p Plan) Validate() error {
	for _, v := range []struct {
		key   string
		value int64
	}{
		{"trials", int64(p.Trials)}, {"trial_cap_usd", int64(p.TrialCapUSD)},
		{"max_output_tokens", int64(p.MaxOutputTokens)}, {"concurrency", int64(p.Concurrency)},
	} {
		if v.value < 1 {
			return goerr.New("every [plan] value must be more than zero",
				goerr.V("key", v.key), goerr.V("value", v.value))
		}
	}
	return nil
}

// The forecast's assumption about one expected LLM call: rounded up from the mean call of the
// dearest candidate when the scenarios were last measured (2,945 input tokens, almost all of them
// cache reads and writes, and 256 output tokens), with the input priced as uncached.
const (
	ForecastInputTokens  = 3000
	ForecastOutputTokens = 300
)

// ForecastLine is the forecast cost of one candidate's trials of one scenario.
type ForecastLine struct {
	Candidate string          `json:"candidate"`
	Role      Role            `json:"role"`
	Scenario  string          `json:"scenario"`
	Trials    int             `json:"trials"`
	Calls     int             `json:"calls"`
	NanoUSD   pricing.NanoUSD `json:"nano_usd"`
}

// Forecast is what trials runs of every scenario would cost at rate.
func Forecast(candidate string, rate pricing.Rate, scenarios []Scenario, trials int) []ForecastLine {
	per := rate.Cost(ForecastInputTokens, ForecastOutputTokens, 0, 0)
	out := make([]ForecastLine, 0, len(scenarios))
	for _, s := range scenarios {
		out = append(out, ForecastLine{Candidate: candidate, Role: s.Kind.Role(), Scenario: s.ID, Trials: trials,
			Calls: s.ExpectedCalls, NanoUSD: pricing.NanoUSD(trials*s.ExpectedCalls) * per})
	}
	return out
}
