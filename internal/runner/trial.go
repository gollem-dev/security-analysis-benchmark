package runner

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"

	"github.com/gollem-dev/agentkit"
	"github.com/gollem-dev/gollem"
	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

// trialAgent is the strategy one trial runs: an episode on its candidate's model, whose tool calls
// the scenario's environment answers, until the candidate calls a final tool.
const trialAgent agentkit.AgentName = "bench_trial"

// trialMetadataKey is the process metadata naming the trial, which the tool factory reads.
const trialMetadataKey = "bench_trial"

// trialInput names the trial and the candidate. The scenario stays in the run's memory: its tools
// are answered by functions that cannot be encoded into a state.
type trialInput struct {
	Key       string `json:"key"`
	Candidate string `json:"candidate"`
}

// liveTrial is what one running trial reads: its scenario's opening request, its environment and the
// tools that end it.
type liveTrial struct {
	request bench.Request
	env     bench.Env
	final   []string
}

// liveTrials is the run's running trials by trial key.
type liveTrials struct {
	mu sync.Mutex
	m  map[string]*liveTrial
}

func (l *liveTrials) put(key string, t *liveTrial) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[key] = t
}

func (l *liveTrials) drop(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

func (l *liveTrials) get(key string) (*liveTrial, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.m[key]
	return t, ok
}

// tools is the kernel's tool factory: the tools of the trial's own scenario and no other, each
// answered by the trial's environment. A process naming no trial gets an error rather than another
// scenario's tools.
func (l *liveTrials) tools(_ context.Context, proc *agentkit.Process) ([]gollem.Tool, error) {
	key := proc.Metadata[trialMetadataKey]
	t, ok := l.get(key)
	if !ok {
		return nil, goerr.New("a process names no running trial", goerr.V("key", key), goerr.V("process_id", string(proc.ID)))
	}
	out := make([]gollem.Tool, 0, len(t.request.Tools))
	for _, spec := range t.request.Tools {
		out = append(out, envTool{spec: spec, env: t.env})
	}
	return out, nil
}

// envTool is one of a scenario's tools, answered by its environment.
type envTool struct {
	spec gollem.ToolSpec
	env  bench.Env
}

func (t envTool) Spec() gollem.ToolSpec { return t.spec }

func (t envTool) Run(ctx context.Context, args map[string]any) (map[string]any, error) {
	return t.env.Call(ctx, t.spec.Name, args), nil
}

type trialState struct {
	Input   trialInput   `json:"input"`
	Started bool         `json:"started"`
	Calls   []bench.Call `json:"calls,omitempty"`
	// Pending is the last generate's tool calls, which the next transition runs.
	Pending []*gollem.FunctionCall `json:"pending,omitempty"`
}

type trialOutput struct {
	bench.Transcript
}

type trialStrategy struct {
	trials *liveTrials
	roles  map[string]agentkit.ModelRole
	rates  map[string]pricing.Rate
}

var _ agentkit.Strategy[trialState, trialInput, trialOutput] = (*trialStrategy)(nil)

func (s *trialStrategy) Version() int { return 1 }

func (s *trialStrategy) Init(in trialInput) (trialState, error) { return trialState{Input: in}, nil }

// Limit passes: a trial is held to its money by the generate middleware, never by a count.
func (s *trialStrategy) Limit(context.Context, *agentkit.Process, agentkit.Metrics) agentkit.LimitDecision {
	return agentkit.LimitPass()
}

func (s *trialStrategy) EncodeState(state trialState) ([]byte, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to encode a trial's state")
	}
	return raw, nil
}

func (s *trialStrategy) DecodeState(version int, raw []byte) (trialState, error) {
	if version != s.Version() {
		return trialState{}, goerr.New("a trial's state was written by another version", goerr.V("state_version", version))
	}
	var state trialState
	if err := json.Unmarshal(raw, &state); err != nil {
		return trialState{}, goerr.Wrap(err, "failed to decode a trial's state")
	}
	return state, nil
}

func (s *trialStrategy) EncodeOutput(out trialOutput) ([]byte, error) {
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to encode a trial's transcript")
	}
	return raw, nil
}

// Step generates in one transition and runs what the generate called in the next.
//
// GENERATING AND RUNNING ARE SEPARATE TRANSITIONS: a transition that fails after its generate is
// run again, and running it again would pay for the same generate twice if it had also run the tools.
func (s *trialStrategy) Step(ctx context.Context, sys agentkit.Syscalls, state trialState) (
	trialState, agentkit.Decision[trialOutput], error) {
	trial, ok := s.trials.get(state.Input.Key)
	if !ok {
		return state, agentkit.Decision[trialOutput]{}, goerr.New("a trial's scenario is not held", goerr.V("key", state.Input.Key))
	}
	if len(state.Pending) > 0 {
		return s.run(ctx, sys, state, trial)
	}
	return s.generate(ctx, sys, state, trial)
}

func (s *trialStrategy) generate(ctx context.Context, sys agentkit.Syscalls, state trialState, trial *liveTrial) (
	trialState, agentkit.Decision[trialOutput], error) {
	role, ok := s.roles[state.Input.Candidate]
	if !ok {
		return state, agentkit.Decision[trialOutput]{}, goerr.New("a trial names no candidate of this run",
			goerr.V("candidate", state.Input.Candidate))
	}
	var input []gollem.Input
	if !state.Started {
		input = trial.request.Input
	}
	res, err := sys.Session().Generate(ctx, input, agentkit.WithRole(role),
		agentkit.WithSystemPrompt(trial.request.SystemPrompt),
		agentkit.WithLLMSessionOptions(gollem.WithSessionPromptCache(true)))
	var over *overReservationError
	switch {
	case errors.As(err, &over):
		// The run stops here; the call that stopped it was billed and stays in the record.
		state = s.record(state, over.result)
		return state, agentkit.Done(trialOutput{bench.Transcript{Calls: state.Calls, End: bench.EndRunCap}}), nil
	case errors.Is(err, bench.ErrRunCap):
		return state, agentkit.Done(trialOutput{bench.Transcript{Calls: state.Calls, End: bench.EndRunCap}}), nil
	case errors.Is(err, bench.ErrTrialCap):
		return state, agentkit.Done(trialOutput{bench.Transcript{Calls: state.Calls, End: bench.EndCap}}), nil
	case err != nil:
		return state, agentkit.Decision[trialOutput]{}, goerr.Wrap(err, "a trial's generate failed",
			goerr.V("candidate", state.Input.Candidate), goerr.V("trial", state.Input.Key))
	}
	state.Started = true
	state = s.record(state, res)
	if len(res.FunctionCalls) == 0 {
		return state, agentkit.Done(trialOutput{bench.Transcript{Calls: state.Calls, End: bench.EndReply}}), nil
	}
	state.Pending = res.FunctionCalls
	return state, agentkit.Continue[trialOutput](), nil
}

// record adds one generate's output, tokens and cost to the trial's calls.
func (s *trialStrategy) record(state trialState, res *agentkit.GenerateResult) trialState {
	in, out := int64(res.InputTokens), int64(res.OutputTokens)
	read, write := int64(res.CacheReadInputTokens), int64(res.CacheCreationInputTokens)
	state.Calls = append(state.Calls, bench.Call{
		Output:      bench.Output{Texts: res.Texts, FunctionCalls: res.FunctionCalls},
		InputTokens: in, OutputTokens: out, CacheReadTokens: read, CacheWriteTokens: write,
		CostNanoUSD: int64(s.rates[state.Input.Candidate].Cost(in, out, read, write)),
	})
	return state
}

// run answers every call of the last generate. A call the kernel refuses (a tool the scenario does
// not offer, arguments that fail its spec) is answered with the error and stays in the record: it
// is the candidate's mistake, and the next generate reads it.
func (s *trialStrategy) run(ctx context.Context, sys agentkit.Syscalls, state trialState, trial *liveTrial) (
	trialState, agentkit.Decision[trialOutput], error) {
	last := &state.Calls[len(state.Calls)-1]
	last.Results = nil
	finished := false
	for _, fc := range state.Pending {
		result, err := sys.Session().CallTool(ctx, *fc)
		if err != nil {
			result = map[string]any{"error": err.Error()}
		}
		x := bench.ToolExchange{Call: fc, Result: result}
		last.Results = append(last.Results, x)
		// THE FIRST FINAL CALL IS THE ANSWER: the calls after it in the same round are not run, so a
		// second answer cannot replace the first.
		if x.Succeeded() && slices.Contains(trial.final, fc.Name) {
			finished = true
			break
		}
	}
	state.Pending = nil
	if finished {
		return state, agentkit.Done(trialOutput{bench.Transcript{Calls: state.Calls, End: bench.EndFinalTool}}), nil
	}
	return state, agentkit.Continue[trialOutput](), nil
}
