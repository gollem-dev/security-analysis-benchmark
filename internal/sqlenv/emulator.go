package sqlenv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/m-mizutani/goerr/v2"
)

// The emulator is started with the docker command rather than a container library: run, port and
// rm are all a run needs, and the library is a test dependency the run's own path does not need.
const (
	emulatorPort       = "9050/tcp"
	emulatorReady      = 60 * time.Second
	emulatorPollPeriod = 200 * time.Millisecond
)

// startEmulator runs a fresh emulator from image and returns its endpoint and a function that
// removes the container.
func startEmulator(ctx context.Context, image string) (string, func(), error) {
	out, err := docker(ctx, "run", "--detach", "--rm", "--publish", "127.0.0.1::9050",
		"--env", "BIGQUERY_EMULATOR_PROJECT="+Project, image)
	if err != nil {
		return "", nil, err
	}
	id := strings.TrimSpace(out)
	stop := func() {
		// A context of its own: the run's may already be cancelled when the container is removed.
		_, _ = docker(context.Background(), "rm", "--force", id)
	}
	mapped, err := docker(ctx, "port", id, emulatorPort)
	if err != nil {
		stop()
		return "", nil, err
	}
	// One line per address family; the first is the IPv4 address asked for.
	addr, _, _ := strings.Cut(strings.TrimSpace(mapped), "\n")
	endpoint := "http://" + strings.TrimSpace(addr)
	if err := waitReady(ctx, endpoint); err != nil {
		stop()
		return "", nil, err
	}
	return endpoint, stop, nil
}

func docker(ctx context.Context, args ...string) (string, error) {
	// #nosec G204 -- the arguments are this package's own; the image is the operator's flag.
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		stderr := ""
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			stderr = strings.TrimSpace(string(exit.Stderr))
		}
		return "", goerr.Wrap(err, "the docker command failed", goerr.V("args", args), goerr.V("stderr", stderr))
	}
	return string(out), nil
}

// waitReady polls the emulator until it answers a listing of its project's datasets.
func waitReady(ctx context.Context, endpoint string) error {
	deadline := time.Now().Add(emulatorReady)
	url := fmt.Sprintf("%s/projects/%s/datasets", endpoint, Project)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return goerr.Wrap(err, "failed to build the emulator's readiness request", goerr.V("url", url))
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = goerr.New("the emulator answered with an error status", goerr.V("status", resp.StatusCode))
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return goerr.Wrap(ctx.Err(), "stopped waiting for the emulator")
		case <-time.After(emulatorPollPeriod):
		}
	}
	return goerr.Wrap(last, "the BigQuery emulator did not become ready",
		goerr.V("endpoint", endpoint), goerr.V("timeout", emulatorReady.String()))
}
