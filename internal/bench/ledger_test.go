package bench_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

func TestTheLedgerNeverReservesPastItsLimit(t *testing.T) {
	l := bench.NewLedger(100)
	r, err := l.Reserve(60)
	gt.NoError(t, err).Required()
	_, err = l.Reserve(50)
	gt.True(t, errors.Is(err, bench.ErrRunCap))
	gt.NoError(t, r.Settle(30))
	// Settling twice changes nothing.
	gt.NoError(t, r.Settle(1))
	gt.V(t, l.Spent()).Equal(pricing.NanoUSD(30))
	r2, err := l.Reserve(50)
	gt.NoError(t, err).Required()
	gt.True(t, errors.Is(r2.Settle(51), bench.ErrBudgetViolation))
	_, err = l.Reserve(1)
	gt.True(t, errors.Is(err, bench.ErrRunCap))
}

func TestTheLedgerHoldsUnderConcurrentReservations(t *testing.T) {
	l := bench.NewLedger(50)
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 100 {
		wg.Go(func() {
			if _, err := l.Reserve(1); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	gt.N(t, won).Equal(50)
}

func TestWorstCall(t *testing.T) {
	rate := pricing.Rate{Input: 2_000, CacheWrite: 2_500, Output: 10_000}
	gt.V(t, bench.WorstCall(rate, 4_000, 8_000)).Equal(pricing.NanoUSD((4_000+1_000)*2_500 + 8_000*10_000))
}
