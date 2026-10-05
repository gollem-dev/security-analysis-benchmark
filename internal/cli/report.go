package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/m-mizutani/goerr/v2"
	"github.com/urfave/cli/v3"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/publish"
)

func reportCommand(d *deps) *cli.Command {
	return &cli.Command{
		Name:  "report",
		Usage: "Merge saved results into one result and write its report; no model is called",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "result", Usage: "a result.json to merge; repeatable", Required: true},
			&cli.StringFlag{Name: "out", Usage: "the output directory (default ./.eval/bench/report-<time>/)"},
			&cli.StringFlag{Name: "publish", Usage: "also write the page and one SVG chart per role to <dir>/<yyyymmdd>/<id>/, " +
				"and replace <dir>/latest/ with the same files"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error { return d.report(cmd) },
	}
}

func (d *deps) report(cmd *cli.Command) error {
	var sources []bench.Source
	for _, path := range cmd.StringSlice("result") {
		r, err := bench.ReadResult(path)
		if err != nil {
			return err
		}
		sources = append(sources, bench.Source{Result: r, Dir: filepath.Dir(path)})
	}
	out := cmd.String("out")
	if out == "" {
		out = filepath.Join(".eval", "bench", "report-"+d.now().UTC().Format("20060102T150405Z"))
	}
	// A result read alone is merged too, so its trace paths are rewritten for the new directory.
	merged, err := bench.Merge(sources, out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		return goerr.Wrap(err, "failed to create the output directory", goerr.V("out", out))
	}
	index, err := writeReport(out, merged)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(d.stdout, "report written: %s\n", index)
	if root := cmd.String("publish"); root != "" {
		dir, err := publish.Report(root, merged)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(d.stdout, "report published: %s\n", dir)
	}
	return nil
}
