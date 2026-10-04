package bench_test

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
)

func TestAResultRoundTripsAndAnotherFormatIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	r := &bench.Result{FormatVersion: bench.FormatVersion, RunID: "r1", Roles: []bench.RoleResult{{Role: bench.RoleWorker,
		Scenarios: []bench.ScenarioResult{{ID: "api-named", Kind: bench.KindAPI, Difficulty: 1}}}}}
	gt.NoError(t, bench.WriteResult(path, r)).Required()
	info, err := os.Stat(path)
	gt.NoError(t, err).Required()
	gt.V(t, info.Mode().Perm()).Equal(os.FileMode(0o640))
	back, err := bench.ReadResult(path)
	gt.NoError(t, err).Required()
	gt.S(t, back.Roles[0].Scenarios[0].ID).Equal("api-named")

	old := filepath.Join(dir, "old.json")
	gt.NoError(t, os.WriteFile(old, []byte(`{"format_version": 2}`), 0o600)).Required()
	_, err = bench.ReadResult(old)
	gt.Error(t, err)
}

func TestTheManifestRecordsTheTrackedModules(t *testing.T) {
	started := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/gollem-dev/gollem", Version: "v0.29.0"},
		{Path: "github.com/gollem-dev/agentkit", Version: "v0.4.0", Replace: &debug.Module{Path: "../agentkit", Version: "v0.4.1"}},
	}}
	m := bench.ManifestFrom(info, true, "r", "c", "b", started, "img")
	gt.S(t, m.GoVersion).Equal(runtime.Version())
	gt.S(t, m.Sampling).Equal(bench.SamplingProviderDefault)
	gt.S(t, m.Modules["github.com/gollem-dev/gollem"]).Equal("v0.29.0")
	gt.S(t, m.Modules["github.com/gollem-dev/agentkit"]).Equal("v0.4.1")
	gt.S(t, m.Modules["cloud.google.com/go/bigquery"]).Equal("unknown")

	none := bench.ManifestFrom(nil, false, "r", "c", "b", started, "img")
	for _, path := range bench.TrackedModules {
		gt.S(t, none.Modules[path]).Equal("unknown")
	}
}
