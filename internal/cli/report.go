package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/m-mizutani/goerr/v2"
	"github.com/urfave/cli/v3"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/config"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
	"github.com/gollem-dev/security-analysis-benchmark/internal/publish"
	"github.com/gollem-dev/security-analysis-benchmark/internal/scenario"
)

func reportCommand(d *deps) *cli.Command {
	return &cli.Command{
		Name:  "report",
		Usage: "Merge saved results into one result and write its report; no model is called",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "result", Usage: "a result.json to merge; repeatable"},
			&cli.StringFlag{Name: "history", Usage: "take every candidate of --config from its newest result in this directory " +
				"or among --result, in place of merging every result"},
			&cli.StringFlag{Name: "config", Usage: "the configuration whose candidates the report shows; required with --history",
				Sources: cli.EnvVars("BENCHMARK_CONFIG")},
			&cli.StringFlag{Name: "out", Usage: "the output directory (default ./.eval/bench/report-<time>/)"},
			&cli.StringFlag{Name: "publish", Usage: "also write the page and one SVG chart per role to <dir>/<yyyymmdd>/<id>/, " +
				"and replace <dir>/latest/ with the same files"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error { return d.report(cmd) },
	}
}

func (d *deps) report(cmd *cli.Command) error {
	history := cmd.String("history")
	if history == "" && len(cmd.StringSlice("result")) == 0 {
		return goerr.New("there is nothing to report: give --result, or --history with --config")
	}
	var sources []bench.Source
	for _, path := range cmd.StringSlice("result") {
		r, err := bench.ReadResult(path)
		if err != nil {
			return err
		}
		sources = append(sources, bench.Source{Result: r, Dir: filepath.Dir(path)})
	}
	var order []string
	if history != "" {
		picked, names, err := pickFromHistory(history, cmd.String("config"), sources)
		if err != nil {
			return err
		}
		sources, order = picked, names
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
	if order != nil {
		// The configuration's order, so that a candidate keeps its colour whichever run it comes from.
		slices.SortStableFunc(merged.Candidates, func(a, b bench.Candidate) int {
			return slices.Index(order, a.Name) - slices.Index(order, b.Name)
		})
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

// pickFromHistory takes every candidate of the configuration at path from its newest measurement of
// every current scenario of its roles among the history directory's results and the given ones, as
// bench.Pick chooses, and returns those results narrowed to
// the candidates taken from them and the candidates' names in the configuration's order. A candidate
// no result measured is refused, so that a report never leaves one out silently.
func pickFromHistory(history, path string, given []bench.Source) ([]bench.Source, []string, error) {
	if path == "" {
		return nil, nil, goerr.New("--history needs the configuration whose candidates the report shows: set --config or BENCHMARK_CONFIG")
	}
	prices, err := pricing.Embedded()
	if err != nil {
		return nil, nil, err
	}
	// No model is called, so no credential is needed.
	loaded, err := config.Load(path, config.Env{}, prices)
	if err != nil {
		return nil, nil, err
	}
	current, err := scenario.All()
	if err != nil {
		return nil, nil, err
	}
	saved, err := bench.ReadHistory(history)
	if err != nil {
		return nil, nil, err
	}
	var wanted []bench.Wanted
	var names []string
	for _, c := range loaded.Candidates {
		wanted = append(wanted, bench.Wanted{Name: c.Name, Provider: c.Provider, Model: c.Model, Roles: c.Roles, Current: c.Current})
		names = append(names, c.Name)
	}
	picked, missing := bench.Pick(append(saved, given...), wanted, current)
	if len(missing) > 0 {
		// The names are in the message: the command line prints an error's message only.
		return nil, nil, goerr.New("no saved result measured every current scenario of these candidates with their configured "+
			"provider and model: "+strings.Join(missing, ", ")+". Run these candidates, then report again",
			goerr.V("candidates", missing), goerr.V("history", history), goerr.V("config", path))
	}
	return picked, names, nil
}
