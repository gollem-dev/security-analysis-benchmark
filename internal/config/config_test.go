package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/config"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

func prices(t *testing.T) pricing.Table {
	t.Helper()
	p, err := pricing.Embedded()
	gt.NoError(t, err).Required()
	return p
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bench.toml")
	gt.NoError(t, os.WriteFile(p, []byte(body), 0o600)).Required()
	return p
}

const (
	flash  = "\n[[candidates]]\nname = \"flash\"\nprovider = \"gemini\"\nmodel = \"gemini-3.8-flash\"\n"
	sonnet = "\n[[candidates]]\nname = \"sonnet\"\nprovider = \"claude-vertex\"\nmodel = \"claude-sonnet-5-5\"\n"
)

func TestTheBundledConfigurationLoads(t *testing.T) {
	l, err := config.Load(filepath.Join("..", "..", "bench.toml"), config.Env{GoogleCloudProject: "p"}, prices(t))
	gt.NoError(t, err).Required()
	gt.A(t, l.Candidates).Length(3)
	gt.V(t, l.Plan).Equal(bench.DefaultPlan)
	gt.V(t, l.MaxUSD).Equal(pricing.NanoUSD(30_000_000_000))
	for _, c := range l.Candidates {
		gt.A(t, c.Roles).Equal(bench.Roles)
	}
}

func TestAPlanOverridesTheDefaults(t *testing.T) {
	l, err := config.Load(write(t, "[plan]\ntrials = 2\ntrial_cap_usd = \"0.50\"\nmax_output_tokens = 4000\n"+flash+
		"roles = [\"worker\", \"worker\"]\ncurrent = [\"worker\"]\n"), config.Env{GoogleCloudProject: "p"}, prices(t))
	gt.NoError(t, err).Required()
	gt.N(t, l.Plan.Trials).Equal(2)
	gt.V(t, l.Plan.TrialCapUSD).Equal(pricing.NanoUSD(500_000_000))
	gt.N(t, l.Plan.MaxOutputTokens).Equal(4000)
	gt.N(t, l.Plan.Concurrency).Equal(4)
	gt.S(t, l.MaxUSDRaw).Equal(config.DefaultMaxUSD)
	gt.A(t, l.Candidates[0].Roles).Equal([]bench.Role{bench.RoleWorker})
	gt.A(t, l.Candidates[0].Current).Equal([]bench.Role{bench.RoleWorker})
}

func TestTargetFor(t *testing.T) {
	type target = config.GoogleCloudTarget
	cases := []struct {
		env         config.Env
		gemini, vtx target
	}{
		{config.Env{GoogleCloudProject: "p"},
			target{"p", "global", config.EnvGoogleCloudProject, "default"},
			target{"p", "global", config.EnvGoogleCloudProject, "default"}},
		{config.Env{GoogleCloudProject: "p", ClaudeVertexProject: "c"},
			target{"p", "global", config.EnvGoogleCloudProject, "default"},
			target{"c", "global", config.EnvClaudeVertexProject, "default"}},
		{config.Env{GeminiProject: "g", ClaudeVertexProject: "c"},
			target{"g", "global", config.EnvGeminiProject, "default"},
			target{"c", "global", config.EnvClaudeVertexProject, "default"}},
		{config.Env{GoogleCloudProject: "p", GoogleCloudLocation: "us-central1", ClaudeVertexLocation: "global"},
			target{"p", "us-central1", config.EnvGoogleCloudProject, config.EnvGoogleCloudLocation},
			target{"p", "global", config.EnvGoogleCloudProject, config.EnvClaudeVertexLocation}},
	}
	for _, c := range cases {
		g, ok := c.env.TargetFor(config.ProviderGemini)
		gt.B(t, ok).True()
		gt.V(t, g).Equal(c.gemini)
		v, ok := c.env.TargetFor(config.ProviderClaudeVertex)
		gt.B(t, ok).True()
		gt.V(t, v).Equal(c.vtx)
	}
	_, ok := config.Env{GoogleCloudProject: "p"}.TargetFor(config.ProviderClaude)
	gt.B(t, ok).False()
}

func TestEachProvidersProjectAndLocationAreChecked(t *testing.T) {
	onlyGemini := config.Env{GeminiProject: "g"}
	_, err := config.Load(write(t, flash+sonnet), onlyGemini, prices(t))
	gt.Error(t, err).Required()
	gt.S(t, err.Error()).Contains(config.EnvClaudeVertexProject)
	gt.S(t, err.Error()).Contains(config.EnvGoogleCloudProject)
	_, err = config.Load(write(t, flash), onlyGemini, prices(t))
	gt.NoError(t, err)

	regional := config.Env{GoogleCloudProject: "p", GoogleCloudLocation: "us-central1"}
	_, err = config.Load(write(t, flash+sonnet), regional, prices(t))
	gt.Error(t, err)
	regional.ClaudeVertexLocation = "global"
	_, err = config.Load(write(t, flash+sonnet), regional, prices(t))
	gt.NoError(t, err)
	for _, loc := range []string{"us", "us-east5"} {
		_, err = config.Load(write(t, sonnet), config.Env{GoogleCloudProject: "p", GoogleCloudLocation: loc}, prices(t))
		gt.Error(t, err)
	}
	_, err = config.Load(write(t, flash), config.Env{GoogleCloudProject: "p", GoogleCloudLocation: "us-east5"}, prices(t))
	gt.NoError(t, err)
}

func TestAnInvalidConfigurationIsRefused(t *testing.T) {
	env := config.Env{GoogleCloudProject: "p"}
	claude := "\n[[candidates]]\nname = \"c\"\nprovider = \"claude\"\nmodel = \"claude-opus-5-5\"\n"
	openai := "\n[[candidates]]\nname = \"o\"\nprovider = \"openai\"\nmodel = \"gemini-2.5-flash\"\n"
	for name, body := range map[string]string{
		"an unknown key":               "colour = 1\n" + flash,
		"a candidate's project":        flash + "project = \"p\"\n",
		"a candidate's location":       flash + "location = \"global\"\n",
		"a zero max_usd":               "max_usd = \"0\"\n" + flash,
		"max_usd not in dollars":       "max_usd = \"$5\"\n" + flash,
		"a cap not in dollars":         "[plan]\ntrial_cap_usd = \"lots\"\n" + flash,
		"a zero plan value":            "[plan]\ntrials = 0\n" + flash,
		"no candidate":                 "max_usd = \"1.00\"\n",
		"a duplicate name":             flash + flash,
		"an empty name":                "\n[[candidates]]\nname = \"\"\nprovider = \"gemini\"\nmodel = \"gemini-3.8-flash\"\n",
		"a name with a slash":          "\n[[candidates]]\nname = \"a/b\"\nprovider = \"gemini\"\nmodel = \"gemini-3.8-flash\"\n",
		"an unknown provider":          "\n[[candidates]]\nname = \"x\"\nprovider = \"bedrock\"\nmodel = \"gemini-3.8-flash\"\n",
		"an unpriced model":            "\n[[candidates]]\nname = \"x\"\nprovider = \"gemini\"\nmodel = \"no-such-model\"\n",
		"claude without a key":         claude,
		"openai without a key":         openai,
		"an unknown role":              flash + "roles = [\"planner\"]\n",
		"an unknown current role":      flash + "current = [\"runner.sql\"]\n",
		"current outside of its roles": flash + "roles = [\"worker\"]\ncurrent = [\"orchestrator\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(write(t, body), env, prices(t))
			gt.Error(t, err)
		})
	}
	_, err := config.Load(write(t, claude), config.Env{AnthropicAPIKey: "k"}, prices(t))
	gt.NoError(t, err)
}

// A missing key's error names the variable, and never holds a key's value.
func TestAMissingKeysErrorNamesTheVariable(t *testing.T) {
	_, err := config.Load(write(t, "\n[[candidates]]\nname = \"c\"\nprovider = \"claude\"\nmodel = \"claude-opus-5-5\"\n"),
		config.Env{OpenAIAPIKey: "secret-value"}, prices(t))
	gt.Error(t, err).Required()
	gt.S(t, err.Error()).Contains(config.EnvAnthropicAPIKey)
	gt.S(t, err.Error()).NotContains("secret-value")
}
