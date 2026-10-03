package runner

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/gollem-dev/agentkit"
	gollemtrace "github.com/gollem-dev/gollem/trace"
	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
)

// Trace events and labels beyond what gollem records itself.
const (
	traceEventTransition  = "transition"
	traceEventClaimResult = "claim_result"
	traceLabelRevision    = "build_revision"
)

// traces holds every claim's execution trace, gzipped JSON, by process, until the run ends and they
// are filed under their trials. They are held in memory because the output directory is named after
// the run, which is known only once the run is over.
type traces struct {
	mu     sync.Mutex
	byPID  map[agentkit.ProcessID][][]byte
	logger *slog.Logger
}

func newTraces(logger *slog.Logger) *traces {
	return &traces{byPID: map[agentkit.ProcessID][][]byte{}, logger: logger}
}

func (t *traces) save(pid agentkit.ProcessID, tr *gollemtrace.Trace) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(tr); err != nil {
		return goerr.Wrap(err, "failed to encode a trace", goerr.V("process_id", string(pid)))
	}
	if err := zw.Close(); err != nil {
		return goerr.Wrap(err, "failed to compress a trace", goerr.V("process_id", string(pid)))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byPID[pid] = append(t.byPID[pid], buf.Bytes())
	return nil
}

// claimRepo is the trace repository of one claim: it files the claim's trace under its process.
type claimRepo struct {
	t   *traces
	pid agentkit.ProcessID
}

func (r claimRepo) Save(_ context.Context, tr *gollemtrace.Trace) error { return r.t.save(r.pid, tr) }

// claim records one gollem trace per claim, labelled with the commit the run was built from, and
// saves it when the claim ends, a panic included.
func (t *traces) claim(commit string) agentkit.ClaimMiddleware {
	return func(next agentkit.ClaimHandler) agentkit.ClaimHandler {
		return func(ctx context.Context, req *agentkit.ClaimRequest) (outcome agentkit.ClaimOutcome, err error) {
			p := req.Process
			rec := gollemtrace.New(
				gollemtrace.WithTraceID(p.LeaseToken),
				gollemtrace.WithRepository(claimRepo{t: t, pid: p.ID}),
				gollemtrace.WithMetadata(gollemtrace.TraceMetadata{Strategy: string(p.Agent), Labels: map[string]string{
					"process_id": string(p.ID), "trial": p.Metadata[trialMetadataKey],
					"state_seq": strconv.Itoa(p.StateSeq), traceLabelRevision: commit,
				}}),
			)
			ctx = gollemtrace.WithHandler(ctx, rec)
			ctx = rec.StartAgentExecute(ctx)
			defer func() {
				if r := recover(); r != nil {
					rec.AddEvent(ctx, traceEventClaimResult, map[string]any{"panicked": true})
					rec.EndAgentExecute(ctx, goerr.New("a claim panicked", goerr.V("panic", fmt.Sprint(r))))
					t.finish(ctx, rec, p.ID)
					panic(r)
				}
				rec.AddEvent(ctx, traceEventClaimResult, map[string]any{"outcome": string(outcome)})
				spanErr := err
				if spanErr == nil && (outcome == agentkit.ClaimRequeued || outcome == agentkit.ClaimAbandoned) {
					spanErr = goerr.New("a claim ended in a fault", goerr.V("outcome", string(outcome)))
				}
				rec.EndAgentExecute(ctx, spanErr)
				t.finish(ctx, rec, p.ID)
			}()
			outcome, err = next(ctx, req)
			return outcome, err
		}
	}
}

func (t *traces) finish(ctx context.Context, rec *gollemtrace.Recorder, pid agentkit.ProcessID) {
	if err := rec.Finish(context.WithoutCancel(ctx)); err != nil {
		t.logger.Error("failed to keep a trace", slog.Any("error", goerr.Wrap(err, "failed to keep a trace",
			goerr.V("process_id", string(pid)))))
	}
}

// step marks where each transition starts within a claim's trace.
func (t *traces) step() agentkit.StepMiddleware {
	return func(next agentkit.StepHandler) agentkit.StepHandler {
		return func(ctx context.Context, req *agentkit.StepRequest) (*agentkit.StepResult, error) {
			if h := gollemtrace.HandlerFrom(ctx); h != nil {
				h.AddEvent(ctx, traceEventTransition, map[string]any{
					"state_seq": req.Effect.StateSeq, "attempt_errors": req.Effect.Attempt.Errors,
					"replay": req.Effect.Attempt.IsReplay(),
				})
			}
			return next(ctx, req)
		}
	}
}

// toolCall wraps every tool call in a span: the kernel calls tools without gollem's own agent loop,
// which would otherwise add it.
func (t *traces) toolCall() agentkit.ToolCallMiddleware {
	return func(next agentkit.ToolCallHandler) agentkit.ToolCallHandler {
		return func(ctx context.Context, req *agentkit.ToolCallRequest) (out map[string]any, err error) {
			h := gollemtrace.HandlerFrom(ctx)
			if h == nil {
				return next(ctx, req)
			}
			ctx = h.StartToolExec(ctx, req.Call.Name, req.Call.Arguments)
			defer func() {
				if r := recover(); r != nil {
					h.EndToolExec(ctx, nil, goerr.New("a tool call panicked", goerr.V("panic", fmt.Sprint(r))))
					panic(r)
				}
				h.EndToolExec(ctx, out, err)
			}()
			out, err = next(ctx, req)
			return out, err
		}
	}
}

// file names the process's traces under dir, in the order its claims ended.
func (t *traces) file(pid agentkit.ProcessID, dir string) []bench.TraceFile {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []bench.TraceFile
	for i, body := range t.byPID[pid] {
		out = append(out, bench.TraceFile{Path: fmt.Sprintf("%s/%03d.json.gz", dir, i+1), Body: body})
	}
	return out
}

// traceDir is where a trial's traces are filed, relative to the run's output directory.
func traceDir(role bench.Role, scenario, candidate string, trial int) string {
	return fmt.Sprintf("traces/%s/%s/%s/%d", role, scenario, candidate, trial)
}
