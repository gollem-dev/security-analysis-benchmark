// Package runner runs the benchmark: it records a run's forecast cost, runs every trial as a process on an
// agentkit kernel whose middlewares hold the run to its money and record its traces, grades every
// transcript and assembles the result.
package runner

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gollem-dev/agentkit"
	historymemory "github.com/gollem-dev/agentkit/historystore/memory"
	repomemory "github.com/gollem-dev/agentkit/repository/memory"
	"github.com/gollem-dev/gollem"
	"github.com/m-mizutani/goerr/v2"
	"golang.org/x/sync/errgroup"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/config"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
	"github.com/gollem-dev/security-analysis-benchmark/internal/sqlenv"
)

// DefaultTrialTimeout is how long a trial is waited for when Config names no timeout.
const DefaultTrialTimeout = 20 * time.Minute

// Config is what one run needs.
type Config struct {
	Loaded         *config.Loaded
	Prices         pricing.Table
	Commit, Branch string
	// EmulatorImage is the BigQuery emulator the SQL scenarios load into; empty is sqlenv.DefaultImage.
	EmulatorImage string
	Logger        *slog.Logger
	// Clients replaces a candidate's client; nil builds it from the candidate. Tests set it.
	Clients func(ctx context.Context, c config.Candidate) (gollem.LLMClient, error)
	// TrialTimeout bounds the wait for one trial; zero is DefaultTrialTimeout.
	TrialTimeout time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// run is what one run's trials share.
type run struct {
	cfg    Config
	plan   bench.Plan
	logger *slog.Logger
	kernel *agentkit.Kernel
	agent  agentkit.Agent[trialInput]
	trials *liveTrials
	ledger *bench.Ledger
	traces *traces

	mu sync.Mutex
	// pids is each started trial's process, by trial key, for filing its traces.
	pids map[string]agentkit.ProcessID
	// trialSpent is what each running trial's calls cost, for its cap.
	trialSpent map[agentkit.ProcessID]pricing.NanoUSD
	// stopped is set once a call found no room under max_usd or cost more than its reservation:
	// no trial starts after it.
	stopped   bool
	violation *bench.BudgetViolation
}

// prepared is one scenario with what its trials need.
type prepared struct {
	scenario bench.Scenario
	result   *bench.ScenarioResult
	sql      bench.SQLRunner
	close    func()
}

// Run runs scenarios with the candidates that evaluate their roles. The run never spends more than
// max_usd: the trials left when it is reached are not run.
func Run(ctx context.Context, cfg Config, scenarios []bench.Scenario) (*bench.Result, error) {
	if cfg.TrialTimeout <= 0 {
		cfg.TrialTimeout = DefaultTrialTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.EmulatorImage == "" {
		cfg.EmulatorImage = sqlenv.DefaultImage
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	started := cfg.Now().UTC()
	loaded := cfg.Loaded
	evaluates := func(c config.Candidate, s bench.Scenario) bool { return slices.Contains(c.Roles, s.Kind.Role()) }
	scenarios = slices.DeleteFunc(slices.Clone(scenarios), func(s bench.Scenario) bool {
		return !slices.ContainsFunc(loaded.Candidates, func(c config.Candidate) bool { return evaluates(c, s) })
	})
	if len(scenarios) == 0 {
		return nil, goerr.New("no candidate evaluates the role of any selected scenario")
	}
	order := func(k bench.Kind) int { return slices.Index(bench.Kinds, k) }
	slices.SortStableFunc(scenarios, func(a, b bench.Scenario) int {
		return cmp.Or(cmp.Compare(slices.Index(bench.Roles, a.Kind.Role()), slices.Index(bench.Roles, b.Kind.Role())),
			cmp.Compare(order(a.Kind), order(b.Kind)), cmp.Compare(a.Difficulty, b.Difficulty))
	})

	var lines []bench.ForecastLine
	for _, c := range loaded.Candidates {
		rate, ok := cfg.Prices.RateOf(c.Model)
		if !ok {
			return nil, goerr.New("a candidate's model has no price", goerr.V("candidate", c.Name), goerr.V("model", c.Model))
		}
		mine := slices.DeleteFunc(slices.Clone(scenarios), func(s bench.Scenario) bool { return !evaluates(c, s) })
		lines = append(lines, bench.Forecast(c.Name, rate, mine, loaded.Plan.Trials)...)
	}

	r := &run{cfg: cfg, plan: loaded.Plan, logger: cfg.Logger, trials: &liveTrials{m: map[string]*liveTrial{}},
		ledger: bench.NewLedger(loaded.MaxUSD), traces: newTraces(cfg.Logger),
		pids: map[string]agentkit.ProcessID{}, trialSpent: map[agentkit.ProcessID]pricing.NanoUSD{}}
	stop, err := r.start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()

	runID := started.Format("20060102T150405Z") + "-" + shortCommit(cfg.Commit)
	out := &bench.Result{FormatVersion: bench.FormatVersion, RunID: runID, Commit: cfg.Commit, Branch: cfg.Branch,
		StartedAt: started, MaxUSD: loaded.MaxUSDRaw, Plan: loaded.Plan, Forecast: lines}
	for _, c := range loaded.Candidates {
		out.Candidates = append(out.Candidates, bench.Candidate{Name: c.Name, Provider: c.Provider, Model: c.Model,
			Roles: c.Roles, Current: c.Current, RunID: runID})
	}

	results := make([]bench.ScenarioResult, len(scenarios))
	all := make([]*prepared, len(scenarios))
	for i, s := range scenarios {
		results[i] = bench.ScenarioResult{ID: s.ID, Kind: s.Kind, Difficulty: s.Difficulty, Version: s.Version,
			ExpectedCalls: s.ExpectedCalls, MinActions: s.MinActions, MinRounds: s.MinRounds,
			Trials: []bench.TrialResult{}, Tallies: []bench.CandidateTally{}}
		all[i] = &prepared{scenario: s, result: &results[i]}
	}
	r.prepare(ctx, all)
	defer func() {
		for _, p := range all {
			if p.close != nil {
				p.close()
			}
		}
	}()

	// One trial of every scenario and candidate before the next, so a run that reaches max_usd leaves
	// every scenario and candidate within one trial of the others.
	notRun := map[*prepared]map[string]int{}
	var notRunMu sync.Mutex
	for trial := 1; trial <= loaded.Plan.Trials; trial++ {
		var g errgroup.Group
		g.SetLimit(loaded.Plan.Concurrency)
		for _, p := range all {
			if p.result.Failure != "" {
				continue
			}
			for _, c := range loaded.Candidates {
				if !evaluates(c, p.scenario) {
					continue
				}
				g.Go(func() error {
					res, ran := r.trial(ctx, p, c.Name, trial)
					if !ran || res.End == bench.EndRunCap {
						notRunMu.Lock()
						if notRun[p] == nil {
							notRun[p] = map[string]int{}
						}
						notRun[p][c.Name]++
						notRunMu.Unlock()
					}
					if ran {
						r.mu.Lock()
						p.result.Trials = append(p.result.Trials, res)
						r.mu.Unlock()
					}
					return nil
				})
			}
		}
		_ = g.Wait() // every trial records its own failure
	}
	// A claim's trace is saved when the claim ends, which can be after the poll that saw its trial
	// finish; stopping the kernel waits for every claim.
	stop()

	for _, p := range all {
		slices.SortStableFunc(p.result.Trials, func(x, y bench.TrialResult) int {
			return cmp.Or(strings.Compare(x.Candidate, y.Candidate), cmp.Compare(x.Trial, y.Trial))
		})
		role := p.scenario.Kind.Role()
		for i := range p.result.Trials {
			t := &p.result.Trials[i]
			pid, ok := r.pids[trialKey(role, p.scenario.ID, t.Candidate, t.Trial)]
			if !ok {
				continue
			}
			dir := traceDir(role, p.scenario.ID, t.Candidate, t.Trial)
			if files := r.traces.file(pid, dir); len(files) > 0 {
				t.Trace = dir
				out.Traces = append(out.Traces, files...)
			}
		}
		for _, c := range loaded.Candidates {
			if !evaluates(c, p.scenario) {
				continue
			}
			tally := bench.CandidateTally{Candidate: c.Name, NotRun: notRun[p][c.Name]}
			for _, t := range p.result.Trials {
				if t.Candidate == c.Name {
					tally.Add(t.End, t.Grade, len(t.Calls), t.CostNanoUSD)
				}
			}
			p.result.Tallies = append(p.result.Tallies, tally)
		}
	}
	for _, role := range bench.Roles {
		rr := bench.RoleResult{Role: role}
		for _, sr := range results {
			if sr.Kind.Role() == role {
				rr.Scenarios = append(rr.Scenarios, sr)
			}
		}
		if len(rr.Scenarios) > 0 {
			out.Roles = append(out.Roles, rr)
		}
	}
	for i := range out.Candidates {
		for _, rr := range out.Roles {
			for _, s := range rr.Scenarios {
				for _, t := range s.Trials {
					if t.Candidate == out.Candidates[i].Name {
						out.Candidates[i].CostNanoUSD += t.CostNanoUSD
					}
				}
			}
		}
	}
	out.SpentNanoUSD = int64(r.ledger.Spent())
	r.mu.Lock()
	out.BudgetViolation = r.violation
	r.mu.Unlock()
	manifest := bench.NewRunManifest(runID, cfg.Commit, cfg.Branch, started, cfg.EmulatorImage)
	manifest.Plan = &out.Plan
	out.Runs = []bench.RunManifest{manifest}
	out.FinishedAt = cfg.Now().UTC()
	return out, nil
}

// shortCommit is the commit's first seven characters, "unknown" when there is none.
func shortCommit(commit string) string {
	if commit == "" || commit == "unknown" {
		return "unknown"
	}
	return commit[:min(7, len(commit))]
}

// start builds the candidates' clients and the run's kernel, and serves it. The returned function
// stops serving and waits for every claim to end; calling it again does nothing.
func (r *run) start(ctx context.Context) (func(), error) {
	reg := agentkit.NewRegistry()
	s := &trialStrategy{trials: r.trials, roles: map[string]agentkit.ModelRole{}, rates: map[string]pricing.Rate{}}
	agent, err := agentkit.Register(reg, trialAgent, s.Version(),
		agentkit.Strategy[trialState, trialInput, trialOutput](s), agentkit.WithHistoryStore[trialOutput](historymemory.New()))
	if err != nil {
		return nil, goerr.Wrap(err, "failed to register the trial agent")
	}
	r.agent = agent
	opts := []agentkit.KernelOption{agentkit.WithToolFactory(r.trials.tools)}
	var first gollem.LLMClient
	byRole := map[agentkit.ModelRole]pricing.Rate{}
	for _, c := range r.cfg.Loaded.Candidates {
		var client gollem.LLMClient
		if r.cfg.Clients != nil {
			client, err = r.cfg.Clients(ctx, c)
		} else {
			client, err = c.Client(ctx, r.cfg.Loaded.Env)
		}
		if err != nil {
			return nil, goerr.Wrap(err, "failed to build a candidate's client", goerr.V("candidate", c.Name))
		}
		if first == nil {
			first = client
		}
		role := agentkit.DefineModelRole("bench:" + c.Name)
		s.roles[c.Name] = role
		opts = append(opts, agentkit.WithModelRole(role, client))
		rate, _ := r.cfg.Prices.RateOf(c.Model)
		s.rates[c.Name] = rate
		byRole[role] = rate
	}
	opts = append(opts, agentkit.WithGenerateMiddleware(r.holdToTheLimit(byRole)),
		agentkit.WithClaimMiddleware(r.traces.claim(r.cfg.Commit)), agentkit.WithStepMiddleware(r.traces.step()),
		agentkit.WithToolCallMiddleware(r.traces.toolCall()), agentkit.WithLogger(r.logger))
	r.kernel, err = agentkit.New(repomemory.New(), first, reg, opts...)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to build the kernel")
	}

	serveCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	k, n := r.kernel, r.plan.Concurrency
	go func() {
		defer close(done)
		err := k.Serve(serveCtx, agentkit.WithPollInterval(200*time.Millisecond), agentkit.WithMaxConcurrent(n),
			agentkit.WithPollConcurrency(n),
			agentkit.WithRetryBackoff(func(attempts int) time.Duration { return time.Duration(attempts) * 2 * time.Second }))
		if err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("the kernel stopped serving", slog.Any("error", goerr.Wrap(err, "the kernel stopped serving")))
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}, nil
}

// emulatorAttempts is how many times a scenario's tables are loaded before the scenario is given up.
const emulatorAttempts = 3

// prepare records every scenario's hash and loads the tables of every SQL scenario, one scenario at
// a time: several emulators loaded at once on a busy machine failed their row loads. A scenario
// whose tables cannot be loaded records why and runs no trial.
func (r *run) prepare(ctx context.Context, all []*prepared) {
	for _, p := range all {
		hash, err := p.scenario.Request.Hash()
		if err != nil {
			p.result.Failure = err.Error()
			continue
		}
		p.result.Hash = hash
		if p.scenario.Tables == nil {
			continue
		}
		var db *sqlenv.DB
		var last error
		for attempt := 1; attempt <= emulatorAttempts && db == nil; attempt++ {
			db, last = sqlenv.Start(ctx, r.cfg.EmulatorImage, p.scenario.Tables)
		}
		if db == nil {
			p.result.Failure = last.Error()
			r.logger.Error("a scenario's tables could not be loaded; it runs no trial", slog.Any("error",
				goerr.Wrap(last, "a scenario's tables could not be loaded", goerr.V("scenario", p.scenario.ID),
					goerr.V("attempts", emulatorAttempts), goerr.V("image", r.cfg.EmulatorImage))))
			continue
		}
		p.close = func() {
			if err := db.Close(); err != nil {
				r.logger.Error("failed to remove an emulator", slog.Any("error", err))
			}
		}
		p.sql = db.Query
	}
}

func trialKey(role bench.Role, scenario, candidate string, n int) string {
	return fmt.Sprintf("%s/%s/%s/%d", role, scenario, candidate, n)
}

// trial runs one episode and grades it. ran is false when the run had stopped and the trial did not
// start, or when it was stopped by the run's limit before its first call.
func (r *run) trial(ctx context.Context, p *prepared, candidate string, n int) (bench.TrialResult, bool) {
	r.mu.Lock()
	stopped := r.stopped
	r.mu.Unlock()
	if stopped {
		return bench.TrialResult{}, false
	}
	key := trialKey(p.scenario.Kind.Role(), p.scenario.ID, candidate, n)
	r.trials.put(key, &liveTrial{request: p.scenario.Request, env: p.scenario.Env(p.sql), final: p.scenario.Final})
	defer r.trials.drop(key)

	began := time.Now()
	out := bench.TrialResult{Candidate: candidate, Trial: n}
	transcript, err := r.episode(ctx, key, candidate)
	out.Seconds = time.Since(began).Seconds()
	if err != nil {
		r.logger.Error("a trial ended without an answer", slog.Any("error", goerr.Wrap(err, "a trial ended without an answer",
			goerr.V("candidate", candidate), goerr.V("trial", key))))
		out.End, out.Error = bench.EndError, err.Error()
		if transcript != nil {
			out.Calls = transcript.Calls
		}
	} else {
		if transcript.End == bench.EndRunCap && len(transcript.Calls) == 0 {
			return bench.TrialResult{}, false
		}
		out.End, out.Calls = transcript.End, transcript.Calls
		out.Grade = bench.GradeTranscript(p.scenario, *transcript)
	}
	for _, c := range out.Calls {
		out.CostNanoUSD += c.CostNanoUSD
	}
	r.logger.Info("trial finished", slog.String("trial", key), slog.String("end", string(out.End)),
		slog.Bool("grounded", out.Reach.Grounded()), slog.Int("calls", len(out.Calls)),
		slog.Int("actions", out.Conduct.Actions), slog.String("cost", pricing.NanoUSD(out.CostNanoUSD).USD4()))
	return out, true
}

// partialTranscript is the record of a trial that ended without an answer. The calls it made were
// billed, so they stay in the record with their cost.
func partialTranscript(proc *agentkit.Process) *bench.Transcript {
	partial := &bench.Transcript{End: bench.EndError}
	var state trialState
	if json.Unmarshal(proc.State, &state) == nil {
		partial.Calls = state.Calls
	}
	return partial
}

// episode spawns one trial on the kernel and waits for it to end.
func (r *run) episode(ctx context.Context, key, candidate string) (*bench.Transcript, error) {
	pid, err := r.agent.Spawn(ctx, r.kernel, trialInput{Key: key, Candidate: candidate},
		agentkit.WithMetadata(map[string]string{trialMetadataKey: key}))
	if err != nil {
		return nil, goerr.Wrap(err, "failed to start a trial", goerr.V("trial", key))
	}
	r.mu.Lock()
	r.pids[key] = pid
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.trialSpent, pid)
		r.mu.Unlock()
	}()
	deadline := time.NewTimer(r.cfg.TrialTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		proc, err := r.kernel.GetProcess(ctx, pid)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to read a trial's process", goerr.V("process_id", string(pid)))
		}
		if proc.Status.Terminal() {
			if proc.Status != agentkit.ProcessSucceeded || proc.Output == nil {
				msg := string(proc.Status)
				if proc.Failure != nil {
					msg = proc.Failure.Message
				}
				return partialTranscript(proc), goerr.New("the trial ended without an answer: "+msg, goerr.V("process_id", string(pid)))
			}
			var out trialOutput
			if err := json.Unmarshal(proc.Output, &out); err != nil {
				return nil, goerr.Wrap(err, "failed to decode a trial's transcript", goerr.V("process_id", string(pid)))
			}
			return &out.Transcript, nil
		}
		select {
		case <-ctx.Done():
			return nil, goerr.Wrap(ctx.Err(), "stopped waiting for a trial", goerr.V("trial", key))
		case <-deadline.C:
			if err := r.kernel.Cancel(context.WithoutCancel(ctx), pid, "the benchmark stopped waiting for this trial"); err != nil &&
				!errors.Is(err, agentkit.ErrProcessFinished) {
				r.logger.Error("failed to cancel a trial that timed out", slog.Any("error",
					goerr.Wrap(err, "failed to cancel a trial", goerr.V("trial", key))))
			}
			var partial *bench.Transcript
			if proc, err := r.kernel.GetProcess(context.WithoutCancel(ctx), pid); err == nil {
				partial = partialTranscript(proc)
			}
			return partial, goerr.New("the trial did not end within "+r.cfg.TrialTimeout.String(), goerr.V("process_id", string(pid)))
		case <-ticker.C:
		}
	}
}
