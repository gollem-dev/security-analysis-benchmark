package publish_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/publish"
	"github.com/gollem-dev/security-analysis-benchmark/internal/report"
)

func resultOf(runs ...bench.RunManifest) *bench.Result {
	return &bench.Result{RunID: "first", Runs: runs}
}

func TestTheDirectoryIsDatedByTheNewestRunAndNamedByTheRuns(t *testing.T) {
	a := bench.RunManifest{RunID: "a", StartedAt: time.Date(2026, 10, 3, 23, 0, 0, 0, time.UTC)}
	b := bench.RunManifest{RunID: "b", StartedAt: time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)}
	ab, err := publish.Dir("results", resultOf(a, b))
	gt.NoError(t, err).Required()
	gt.S(t, filepath.Dir(ab)).Equal(filepath.Join("results", "20261004"))
	gt.S(t, filepath.Base(ab)).Match(`^[0-9a-f]{8}$`)

	// The same runs in another order publish to the same place; other runs do not.
	ba, err := publish.Dir("results", resultOf(b, a))
	gt.NoError(t, err).Required()
	gt.S(t, ba).Equal(ab)
	onlyB, err := publish.Dir("results", resultOf(b))
	gt.NoError(t, err).Required()
	gt.S(t, onlyB).NotEqual(ab)

	_, err = publish.Dir("results", resultOf())
	gt.Error(t, err)
}

func TestWriteWritesThePageAndOneSVGPerRole(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "20261004", "abcd1234")
	charts := []report.Chart{{Role: "orchestrator", SVG: []byte("<svg>o</svg>")}, {Role: "worker", SVG: []byte("<svg>w</svg>")}}
	gt.NoError(t, publish.Write(dir, []byte("<html>"), charts)).Required()
	for name, want := range map[string]string{"index.html": "<html>", "orchestrator.svg": "<svg>o</svg>", "worker.svg": "<svg>w</svg>"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		gt.NoError(t, err).Required()
		gt.S(t, string(got)).Equal(want)
	}
}

func TestReportKeepsItsOwnDirectoryAndReplacesTheLatest(t *testing.T) {
	root := t.TempDir()
	// A file the previous latest report had and the new one does not.
	gt.NoError(t, os.MkdirAll(filepath.Join(root, publish.Latest), 0o750)).Required()
	gt.NoError(t, os.WriteFile(filepath.Join(root, publish.Latest, "orchestrator.svg"), []byte("old"), 0o600)).Required()

	r := everyState()
	dir, err := publish.Report(root, r)
	gt.NoError(t, err).Required()
	want, err := publish.Dir(root, r)
	gt.NoError(t, err).Required()
	gt.S(t, dir).Equal(want)

	for _, d := range []string{dir, filepath.Join(root, publish.Latest)} {
		entries, err := os.ReadDir(d)
		gt.NoError(t, err).Required()
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		gt.A(t, names).Equal([]string{"index.html", "worker.svg"})
	}
	own, err := os.ReadFile(filepath.Join(dir, "worker.svg"))
	gt.NoError(t, err).Required()
	latest, err := os.ReadFile(filepath.Join(root, publish.Latest, "worker.svg"))
	gt.NoError(t, err).Required()
	gt.S(t, string(latest)).Equal(string(own))
}

// everyState is a result of one worker scenario and one run.
func everyState() *bench.Result {
	return &bench.Result{RunID: "r1", Runs: []bench.RunManifest{{RunID: "r1", StartedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)}},
		Candidates: []bench.Candidate{{Name: "a", Provider: "gemini", Model: "gemini-3.8-flash"}},
		Roles: []bench.RoleResult{{Role: bench.RoleWorker, Scenarios: []bench.ScenarioResult{{ID: "api-named", Kind: bench.KindAPI,
			Difficulty: 1, Tallies: []bench.CandidateTally{{Candidate: "a"}}}}}}}
}
