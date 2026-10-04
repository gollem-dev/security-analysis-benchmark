package bench

import (
	"errors"
	"sync"

	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

// The ledger's refusals.
var (
	ErrRunCap          = errors.New("the run's spending limit leaves no room for the next LLM call")
	ErrTrialCap        = errors.New("the trial's cost cap leaves no room for the next LLM call")
	ErrBudgetViolation = errors.New("an LLM call cost more than was reserved for it")
)

// Ledger holds a run's spending against its limit, shared by every trial of the run.
//
// THE LIMIT IS NEVER CROSSED BY A CALL IN FLIGHT. What a call costs is known only once it returns,
// so stopping once the spending reached the limit would overshoot by every call still running. A
// call is made only once its worst case is reserved, and is settled at its actual cost.
type Ledger struct {
	mu       sync.Mutex
	limit    pricing.NanoUSD
	spent    pricing.NanoUSD
	reserved pricing.NanoUSD
	violated bool
}

// NewLedger is a ledger with nothing spent.
func NewLedger(limit pricing.NanoUSD) *Ledger { return &Ledger{limit: limit} }

// Reservation is the worst case held for one call.
type Reservation struct {
	l     *Ledger
	worst pricing.NanoUSD
	done  bool
}

// Reserve holds worst for one call. It fails with ErrRunCap when the limit leaves no room for it,
// and after any violation.
func (l *Ledger) Reserve(worst pricing.NanoUSD) (*Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.violated || l.spent+l.reserved+worst > l.limit {
		return nil, ErrRunCap
	}
	l.reserved += worst
	return &Reservation{l: l, worst: worst}, nil
}

// Settle replaces the reservation with what the call cost; a second Settle does nothing. A call
// that cost more than its reservation is a violation: every later reservation is refused, and Settle
// returns ErrBudgetViolation.
func (r *Reservation) Settle(actual pricing.NanoUSD) error {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return nil
	}
	r.done = true
	l.reserved -= r.worst
	l.spent += actual
	if actual > r.worst {
		l.violated = true
		return ErrBudgetViolation
	}
	return nil
}

// Spent is what the settled calls cost.
func (l *Ledger) Spent() pricing.NanoUSD {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spent
}

// RequestOverheadTokens covers what a provider adds around a request: role markers, the wrapping
// of the tool definitions, its own tool-use instructions.
const RequestOverheadTokens = 1000

// WorstCall is the most one LLM call can cost. A token stands for at least one byte of text, so the
// request's bytes bound its input tokens; they are priced at the higher of the uncached input and
// the cache-write price, and maxOutput output tokens at the output price.
func WorstCall(rate pricing.Rate, requestBytes, maxOutput int) pricing.NanoUSD {
	in := max(rate.Input, rate.CacheWrite)
	return pricing.NanoUSD(requestBytes+RequestOverheadTokens)*in + pricing.NanoUSD(maxOutput)*rate.Output
}
