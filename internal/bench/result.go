package bench

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/m-mizutani/goerr/v2"
)

// FormatVersion is the shape of a Result. A reader refuses any other value.
const FormatVersion = 3

// BudgetViolation is the call that cost more than was reserved for it.
type BudgetViolation struct {
	ActualNanoUSD   int64 `json:"actual_nano_usd"`
	ReservedNanoUSD int64 `json:"reserved_nano_usd"`
	RequestBytes    int   `json:"request_bytes"`
}

// Candidate is one evaluated model.
type Candidate struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Roles    []Role `json:"roles"`
	// Current lists the roles the configuration names this candidate the baseline of.
	Current     []Role `json:"current,omitempty"`
	CostNanoUSD int64  `json:"cost_nano_usd"`
	// RunID is the run the candidate was measured in.
	RunID string `json:"run_id,omitempty"`
}

// TrialResult is one candidate's episode on one scenario.
type TrialResult struct {
	Candidate string `json:"candidate"`
	Trial     int    `json:"trial"`
	End       End    `json:"end"`
	Calls     []Call `json:"calls"`
	Grade
	// CostNanoUSD is what the trial's calls cost by the tokens their providers reported.
	CostNanoUSD int64   `json:"cost_nano_usd"`
	Seconds     float64 `json:"seconds"`
	// Error is why the trial ended in an error; such a trial is not counted.
	Error string `json:"error,omitempty"`
	// Trace is the directory of the trial's execution traces, relative to the result's directory.
	Trace string `json:"trace,omitempty"`
}

// ScenarioResult is one scenario, its trials and each candidate's tally of them.
type ScenarioResult struct {
	ID            string `json:"id"`
	Kind          Kind   `json:"kind"`
	Difficulty    int    `json:"difficulty"`
	Version       int    `json:"version"`
	Hash          string `json:"hash,omitempty"`
	ExpectedCalls int    `json:"expected_calls"`
	MinActions    int    `json:"min_actions"`
	MinRounds     int    `json:"min_rounds,omitempty"`
	// Failure is why the scenario could not be prepared; it has no trials.
	Failure string           `json:"failure,omitempty"`
	Trials  []TrialResult    `json:"trials"`
	Tallies []CandidateTally `json:"tallies"`
}

// Tally is the candidate's tally of the scenario, and false when there is none.
func (s ScenarioResult) Tally(candidate string) (CandidateTally, bool) {
	for _, t := range s.Tallies {
		if t.Candidate == candidate {
			return t, true
		}
	}
	return CandidateTally{}, false
}

// RoleResult is every scenario of one role, by kind in the order of Kinds and then by difficulty.
type RoleResult struct {
	Role      Role             `json:"role"`
	Scenarios []ScenarioResult `json:"scenarios"`
}

// ExcludedScenario is a scenario a merge left out, and why.
type ExcludedScenario struct {
	Role     Role   `json:"role"`
	Scenario string `json:"scenario"`
	Reason   string `json:"reason"`
}

// TraceFile is one claim's execution trace, gzipped JSON, at Path relative to the output directory.
type TraceFile struct {
	Path string
	Body []byte
}

// SamplingProviderDefault records that no sampling parameter was sent: every provider generated with
// its own defaults.
const SamplingProviderDefault = "provider-default"

// TrackedModules are the dependencies whose versions a run records.
var TrackedModules = []string{"github.com/gollem-dev/gollem", "github.com/gollem-dev/agentkit", "cloud.google.com/go/bigquery"}

// unknown stands for a value that could not be found out.
const unknown = "unknown"

// RunManifest is the conditions one run measured under.
type RunManifest struct {
	RunID         string            `json:"run_id"`
	Commit        string            `json:"commit"`
	Branch        string            `json:"branch"`
	StartedAt     time.Time         `json:"started_at"`
	GoVersion     string            `json:"go_version"`
	Modules       map[string]string `json:"modules"`
	EmulatorImage string            `json:"emulator_image"`
	Sampling      string            `json:"sampling"`
	// Plan is the plan the run's candidates were measured under; nil in a result written before runs
	// recorded it, whose candidates were measured under the result's own Plan.
	Plan *Plan `json:"plan,omitempty"`
}

// NewRunManifest records the run's conditions, with the versions of TrackedModules read from the
// binary's build information.
func NewRunManifest(runID, commit, branch string, startedAt time.Time, emulatorImage string) RunManifest {
	info, ok := debug.ReadBuildInfo()
	return manifestFrom(info, ok, runID, commit, branch, startedAt, emulatorImage)
}

func manifestFrom(info *debug.BuildInfo, ok bool, runID, commit, branch string, startedAt time.Time, emulatorImage string) RunManifest {
	m := RunManifest{RunID: runID, Commit: commit, Branch: branch, StartedAt: startedAt,
		GoVersion: runtime.Version(), Modules: map[string]string{}, EmulatorImage: emulatorImage,
		Sampling: SamplingProviderDefault}
	for _, path := range TrackedModules {
		m.Modules[path] = unknown
	}
	if !ok || info == nil {
		return m
	}
	for _, dep := range info.Deps {
		if _, tracked := m.Modules[dep.Path]; !tracked {
			continue
		}
		version := dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}
		if version != "" {
			m.Modules[dep.Path] = version
		}
	}
	return m
}

// Result is one benchmark run, or several merged.
type Result struct {
	FormatVersion int            `json:"format_version"`
	RunID         string         `json:"run_id"`
	Commit        string         `json:"commit"`
	Branch        string         `json:"branch"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    time.Time      `json:"finished_at"`
	MaxUSD        string         `json:"max_usd"`
	Plan          Plan           `json:"plan"`
	Forecast      []ForecastLine `json:"forecast"`
	// SpentNanoUSD is what the ledger settled: every call, the trials not counted included.
	SpentNanoUSD    int64            `json:"spent_nano_usd"`
	BudgetViolation *BudgetViolation `json:"budget_violation,omitempty"`
	// Runs is the conditions of the run, or of every run a merge put together.
	Runs       []RunManifest      `json:"runs"`
	Candidates []Candidate        `json:"candidates"`
	Roles      []RoleResult       `json:"roles"`
	Excluded   []ExcludedScenario `json:"excluded,omitempty"`
	// Traces are the trials' execution traces, written beside the result; never part of it.
	Traces []TraceFile `json:"-"`
}

// PlanOf is the plan the candidate was measured under: its run's, so that a merge of runs with
// different plans scores every candidate by its own. A candidate of no recorded run, or of a run that
// did not record its plan, was measured under the result's Plan.
func (r *Result) PlanOf(candidate string) Plan {
	runID := r.RunID
	for _, c := range r.Candidates {
		if c.Name == candidate && c.RunID != "" {
			runID = c.RunID
		}
	}
	for _, m := range r.Runs {
		if m.RunID == runID && m.Plan != nil {
			return *m.Plan
		}
	}
	return r.Plan
}

// ReadResult reads one result file and refuses a format version this build does not know.
func ReadResult(path string) (*Result, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator names the result to read
	if err != nil {
		return nil, goerr.Wrap(err, "failed to read a result file", goerr.V("path", path))
	}
	var head struct {
		FormatVersion int `json:"format_version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, goerr.Wrap(err, "failed to decode a result file", goerr.V("path", path))
	}
	if head.FormatVersion != FormatVersion {
		return nil, goerr.New("the result file has another format version", goerr.V("path", path),
			goerr.V("format_version", head.FormatVersion), goerr.V("supported", FormatVersion))
	}
	var out Result
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, goerr.Wrap(err, "failed to decode a result file", goerr.V("path", path))
	}
	return &out, nil
}

// WriteResult writes r to path, readable by its owner's group only.
func WriteResult(path string, r *Result) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return goerr.Wrap(err, "failed to encode a result")
	}
	// #nosec G306 -- the result is shared with the owner's group on purpose; it holds no secret.
	if err := os.WriteFile(path, append(raw, '\n'), 0o640); err != nil {
		return goerr.Wrap(err, "failed to write a result file", goerr.V("path", path))
	}
	return nil
}
