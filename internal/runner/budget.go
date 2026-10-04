package runner

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/gollem-dev/agentkit"
	"github.com/gollem-dev/gollem"
	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

// holdToTheLimit is the generate middleware that keeps every call within its trial's cap and the
// run's max_usd: it reserves the call's worst case before the call, settles the actual cost after
// it, and sends the output bound the worst case was computed with.
//
// A CALL THAT FAILED IS SETTLED AT ITS RESERVATION in the ledger: the provider may have billed it,
// and nothing reports what it billed. The trial's own spending counts only what a provider
// reported, so a provider's failure does not use up a trial's cap.
func (r *run) holdToTheLimit(byRole map[agentkit.ModelRole]pricing.Rate) agentkit.GenerateMiddleware {
	return func(next agentkit.GenerateHandler) agentkit.GenerateHandler {
		return func(ctx context.Context, req *agentkit.GenerateRequest) (*agentkit.GenerateResult, error) {
			rate, ok := byRole[req.Role]
			if !ok {
				return nil, goerr.New("a generate names no candidate's role", goerr.V("role", req.Role))
			}
			size, err := requestBytes(req)
			if err != nil {
				return nil, err
			}
			worst := bench.WorstCall(rate, size, r.plan.MaxOutputTokens)
			pid := req.Effect.ProcessID
			r.mu.Lock()
			spent, violated := r.trialSpent[pid], r.violation != nil
			r.mu.Unlock()
			// A violation stops the run before the trial's cap is weighed: the trial's spending then
			// holds the call that crossed its reservation, and would read as the trial's cap.
			if violated {
				return nil, goerr.Wrap(bench.ErrRunCap, "the run stopped after a call cost more than its reservation")
			}
			if spent+worst > r.plan.TrialCapUSD {
				return nil, goerr.Wrap(bench.ErrTrialCap, "the trial's next call does not fit its cap",
					goerr.V("spent", spent.USD4()), goerr.V("worst", worst.USD4()))
			}
			reservation, err := r.ledger.Reserve(worst)
			if err != nil {
				r.mu.Lock()
				r.stopped = true
				r.mu.Unlock()
				return nil, goerr.Wrap(err, "the run's next call does not fit max_usd", goerr.V("worst", worst.USD4()))
			}
			req.LLMOptions = append(req.LLMOptions, gollem.WithMaxTokens(r.plan.MaxOutputTokens))
			res, genErr := next(ctx, req)
			actual := worst
			if res != nil {
				actual = rate.Cost(int64(res.InputTokens), int64(res.OutputTokens),
					int64(res.CacheReadInputTokens), int64(res.CacheCreationInputTokens))
				r.mu.Lock()
				r.trialSpent[pid] += actual
				r.mu.Unlock()
			}
			if err := reservation.Settle(actual); err != nil {
				r.mu.Lock()
				r.stopped = true
				r.violation = &bench.BudgetViolation{ActualNanoUSD: int64(actual), ReservedNanoUSD: int64(worst), RequestBytes: size}
				r.mu.Unlock()
				violation := goerr.Wrap(err, "an LLM call cost more than its reservation",
					goerr.V("actual", actual.USD4()), goerr.V("reserved", worst.USD4()), goerr.V("request_bytes", size))
				r.logger.Error("an LLM call cost more than its reservation; the run stops", slog.Any("error", violation))
				if genErr == nil {
					return nil, &overReservationError{result: res, err: violation}
				}
			}
			return res, genErr
		}
	}
}

// overReservationError is what a call that cost more than its reservation returns. The call was
// billed, so it carries the call's result for the trial to record: the session drops a result
// returned together with an error.
type overReservationError struct {
	result *agentkit.GenerateResult
	err    error
}

func (e *overReservationError) Error() string { return e.err.Error() }
func (e *overReservationError) Unwrap() error { return e.err }

// requestBytes is the size of everything a generate sends: its system prompt, its tools, the
// history it continues and its new input.
func requestBytes(req *agentkit.GenerateRequest) (int, error) {
	specs := make([]gollem.ToolSpec, 0, len(req.Tools))
	for _, t := range req.Tools {
		specs = append(specs, t.Spec())
	}
	raw, err := json.Marshal(struct {
		System  string            `json:"system"`
		Tools   []gollem.ToolSpec `json:"tools"`
		History *gollem.History   `json:"history"`
		Input   []gollem.Input    `json:"input"`
	}{req.SystemPrompt, specs, req.History, req.Input})
	if err != nil {
		return 0, goerr.Wrap(err, "failed to measure a request")
	}
	return len(raw), nil
}
