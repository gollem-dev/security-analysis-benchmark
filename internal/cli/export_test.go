package cli

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/gollem-dev/gollem"

	"github.com/gollem-dev/security-analysis-benchmark/internal/config"
)

// Deps are the replacements a test runs the command line with.
type Deps struct {
	Clients func(ctx context.Context, c config.Candidate) (gollem.LLMClient, error)
	Now     func() time.Time
	Git     func(ctx context.Context) (string, string)
}

// MainWith is Main with the clients, the clock and git replaced where set.
func MainWith(ctx context.Context, args []string, stdout, stderr io.Writer, t Deps) int {
	d := &deps{clients: t.Clients, now: t.Now, git: t.Git, stdout: stdout, stderr: stderr}
	if d.now == nil {
		d.now = time.Now
	}
	if d.git == nil {
		d.git = gitRevision
	}
	return execute(ctx, args, d)
}

// The pieces the flag and logging tests reach.
var (
	EnvCLIFlags  = envCLIFlags
	EnvFromFlags = envFromFlags
)

// NewLogger is the command line's logger at the named level; it panics on an unknown level.
func NewLogger(w io.Writer, level string) *slog.Logger {
	l, err := newLogger(w, level)
	if err != nil {
		panic(err)
	}
	return l
}
