// Package cli is the benchmark's command line: run measures the candidates, report merges saved
// results into a page, and list shows the scenarios.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/gollem-dev/gollem"
	"github.com/m-mizutani/clog"
	"github.com/m-mizutani/clog/hooks"
	"github.com/m-mizutani/goerr/v2"
	"github.com/urfave/cli/v3"

	"github.com/gollem-dev/security-analysis-benchmark/internal/config"
)

// Main runs the command line and returns its exit code.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, args, &deps{now: time.Now, git: gitRevision, stdout: stdout, stderr: stderr})
}

func execute(ctx context.Context, args []string, d *deps) int {
	if err := newApp(d).Run(ctx, args); err != nil {
		_, _ = fmt.Fprintln(d.stderr, "error:", err)
		return 1
	}
	return 0
}

// deps is what the commands reach outside the process through; tests replace it.
type deps struct {
	// clients builds a candidate's client; nil builds it from the candidate.
	clients func(ctx context.Context, c config.Candidate) (gollem.LLMClient, error)
	now     func() time.Time
	git     func(ctx context.Context) (commit, branch string)
	stdout  io.Writer
	stderr  io.Writer
	logger  *slog.Logger
}

var logLevels = map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}

func newApp(d *deps) *cli.Command {
	return &cli.Command{
		Name:      "security-analysis-benchmark",
		Usage:     "Compare LLMs as an orchestrator and a worker on fixed security analysis scenarios",
		Writer:    d.stdout,
		ErrWriter: d.stderr,
		// Main prints the error once; urfave/cli would otherwise print it and exit by itself.
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-level", Usage: "debug, info, warn or error", Value: "info",
				Sources: cli.EnvVars("BENCHMARK_LOG_LEVEL")},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logger, err := newLogger(d.stderr, cmd.String("log-level"))
			if err != nil {
				return ctx, err
			}
			d.logger = logger
			return ctx, nil
		},
		Commands: []*cli.Command{runCommand(d), reportCommand(d), listCommand(d)},
	}
}

// newLogger writes to w at the named level; a goerr error given as an attribute has its values
// written out with it.
func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	l, ok := logLevels[level]
	if !ok {
		return nil, goerr.New("the log level must be debug, info, warn or error", goerr.V("log_level", level))
	}
	return slog.New(clog.New(clog.WithWriter(w), clog.WithLevel(l), clog.WithAttrHook(hooks.GoErr()))), nil
}

// The flags that give the run its Google Cloud projects and locations and its API keys. Each is
// also read from its environment variable, which the README recommends: a key given as a flag
// stays in the shell's history.
var envFlags = []struct {
	name, env, usage string
	field            func(*config.Env) *string
}{
	{"google-cloud-project", config.EnvGoogleCloudProject, "Google Cloud project of the gemini and claude-vertex candidates",
		func(e *config.Env) *string { return &e.GoogleCloudProject }},
	{"google-cloud-location", config.EnvGoogleCloudLocation, "location of the gemini and claude-vertex candidates (default global)",
		func(e *config.Env) *string { return &e.GoogleCloudLocation }},
	{"gemini-project", config.EnvGeminiProject, "Google Cloud project of the gemini candidates, in place of the common one",
		func(e *config.Env) *string { return &e.GeminiProject }},
	{"gemini-location", config.EnvGeminiLocation, "location of the gemini candidates, in place of the common one",
		func(e *config.Env) *string { return &e.GeminiLocation }},
	{"claude-vertex-project", config.EnvClaudeVertexProject, "Google Cloud project of the claude-vertex candidates, in place of the common one",
		func(e *config.Env) *string { return &e.ClaudeVertexProject }},
	{"claude-vertex-location", config.EnvClaudeVertexLocation, "location of the claude-vertex candidates, in place of the common one; only global is accepted",
		func(e *config.Env) *string { return &e.ClaudeVertexLocation }},
	{"anthropic-api-key", config.EnvAnthropicAPIKey, "API key of the claude candidates",
		func(e *config.Env) *string { return &e.AnthropicAPIKey }},
	{"openai-api-key", config.EnvOpenAIAPIKey, "API key of the openai candidates",
		func(e *config.Env) *string { return &e.OpenAIAPIKey }},
}

func envCLIFlags() []cli.Flag {
	out := make([]cli.Flag, 0, len(envFlags))
	for _, f := range envFlags {
		out = append(out, &cli.StringFlag{Name: f.name, Usage: f.usage, Sources: cli.EnvVars(f.env)})
	}
	return out
}

// envFromFlags is the Env the flags, or their environment variables, give.
func envFromFlags(cmd *cli.Command) config.Env {
	var e config.Env
	for _, f := range envFlags {
		*f.field(&e) = strings.TrimSpace(cmd.String(f.name))
	}
	return e
}

// gitRevision is the commit and branch of the working tree, "unknown" for either git cannot tell. A
// binary built by go run carries no VCS information, so git is asked.
func gitRevision(ctx context.Context) (string, string) {
	read := func(args ...string) string {
		out, err := exec.CommandContext(ctx, "git", args...).Output()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			return "unknown"
		}
		return strings.TrimSpace(string(out))
	}
	return read("rev-parse", "HEAD"), read("rev-parse", "--abbrev-ref", "HEAD")
}
