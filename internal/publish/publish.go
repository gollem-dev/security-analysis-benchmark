// Package publish places a report where the repository serves it: a directory of its own that is
// kept, and a copy at a fixed path that always holds the latest report.
package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/report"
)

// Latest is the directory under the publish root that always holds the latest report, so that a
// README or a link can point at one fixed path. Its files are copies: a README's image cannot follow
// a redirect or a symbolic link.
const Latest = "latest"

// Report writes r's page and charts into its own directory under root and replaces root/latest with
// the same files, and returns the report's own directory.
func Report(root string, r *bench.Result) (string, error) {
	dir, err := Dir(root, r)
	if err != nil {
		return "", err
	}
	var page strings.Builder
	if err := report.Render(&page, r); err != nil {
		return "", err
	}
	charts, err := report.Charts(r)
	if err != nil {
		return "", err
	}
	if err := Write(dir, []byte(page.String()), charts); err != nil {
		return "", err
	}
	latest := filepath.Join(root, Latest)
	// A file the previous latest report had and this one does not, such as a role's chart, must not
	// remain beside it.
	if err := os.RemoveAll(latest); err != nil {
		return "", goerr.Wrap(err, "failed to clear the latest report", goerr.V("dir", latest))
	}
	if err := Write(latest, []byte(page.String()), charts); err != nil {
		return "", err
	}
	return dir, nil
}

// Dir is the directory under root that a report of r is published in: <root>/<yyyymmdd>/<id>. The
// date is the UTC day the newest run started and the id is derived from the run IDs, so publishing
// the same runs again writes the same directory instead of a copy.
func Dir(root string, r *bench.Result) (string, error) {
	if len(r.Runs) == 0 {
		return "", goerr.New("the result names no run, so it has no place to be published", goerr.V("run_id", r.RunID))
	}
	ids := make([]string, 0, len(r.Runs))
	newest := r.Runs[0].StartedAt
	for _, m := range r.Runs {
		ids = append(ids, m.RunID)
		if m.StartedAt.After(newest) {
			newest = m.StartedAt
		}
	}
	slices.Sort(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return filepath.Join(root, newest.UTC().Format("20060102"), hex.EncodeToString(sum[:])[:8]), nil
}

// Write writes the page as index.html and each chart as <role>.svg into dir.
func Write(dir string, page []byte, charts []report.Chart) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return goerr.Wrap(err, "failed to create the publish directory", goerr.V("dir", dir))
	}
	files := map[string][]byte{"index.html": page}
	for _, c := range charts {
		files[c.Role+".svg"] = c.SVG
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		// #nosec G306 -- the published files are meant to be read by anyone.
		if err := os.WriteFile(p, body, 0o644); err != nil {
			return goerr.Wrap(err, "failed to write a published file", goerr.V("path", p))
		}
	}
	return nil
}
