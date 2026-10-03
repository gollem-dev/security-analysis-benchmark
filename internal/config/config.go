// Package config reads and validates the benchmark's TOML configuration. Project IDs, locations and
// API keys are never written in the file; they come from the CLI's flags and environment variables
// as an Env.
package config

import (
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/m-mizutani/goerr/v2"

	"github.com/gollem-dev/security-analysis-benchmark/internal/bench"
	"github.com/gollem-dev/security-analysis-benchmark/internal/pricing"
)

// Providers.
const (
	ProviderGemini       = "gemini"
	ProviderClaudeVertex = "claude-vertex"
	ProviderClaude       = "claude"
	ProviderOpenAI       = "openai"
)

// DefaultMaxUSD is what a run may spend when the configuration names no limit.
const DefaultMaxUSD = "30.00"

// DefaultGoogleCloudLocation is the location of an Agent Platform candidate when none is given.
const DefaultGoogleCloudLocation = "global"

// The environment variables each Env field is read from, as the CLI names them.
const (
	EnvGoogleCloudProject   = "BENCHMARK_GOOGLE_CLOUD_PROJECT"
	EnvGoogleCloudLocation  = "BENCHMARK_GOOGLE_CLOUD_LOCATION"
	EnvGeminiProject        = "BENCHMARK_GEMINI_PROJECT"
	EnvGeminiLocation       = "BENCHMARK_GEMINI_LOCATION"
	EnvClaudeVertexProject  = "BENCHMARK_CLAUDE_VERTEX_PROJECT"
	EnvClaudeVertexLocation = "BENCHMARK_CLAUDE_VERTEX_LOCATION"
	EnvAnthropicAPIKey      = "BENCHMARK_ANTHROPIC_API_KEY"
	EnvOpenAIAPIKey         = "BENCHMARK_OPENAI_API_KEY"
)

// Env is what the run's environment gives it. An empty string is "not given".
type Env struct {
	GoogleCloudProject   string
	GoogleCloudLocation  string
	GeminiProject        string
	GeminiLocation       string
	ClaudeVertexProject  string
	ClaudeVertexLocation string
	AnthropicAPIKey      string
	OpenAIAPIKey         string
}

// GoogleCloudTarget is the project and location an Agent Platform candidate is called in, and the
// environment variable each was taken from ("default" for the default location).
type GoogleCloudTarget struct {
	Project, Location         string
	ProjectFrom, LocationFrom string
}

// TargetFor resolves where provider's candidates are called: the provider's own variable, else the
// common one, and for the location the default after both. ok is false for a provider that does
// not run on the Agent Platform.
func (e Env) TargetFor(provider string) (GoogleCloudTarget, bool) {
	var project, location, projectVar, locationVar string
	switch provider {
	case ProviderGemini:
		project, location, projectVar, locationVar = e.GeminiProject, e.GeminiLocation, EnvGeminiProject, EnvGeminiLocation
	case ProviderClaudeVertex:
		project, location, projectVar, locationVar = e.ClaudeVertexProject, e.ClaudeVertexLocation, EnvClaudeVertexProject, EnvClaudeVertexLocation
	default:
		return GoogleCloudTarget{}, false
	}
	t := GoogleCloudTarget{Project: project, ProjectFrom: projectVar, Location: location, LocationFrom: locationVar}
	if t.Project == "" {
		t.Project, t.ProjectFrom = e.GoogleCloudProject, EnvGoogleCloudProject
	}
	if t.Location == "" {
		t.Location, t.LocationFrom = e.GoogleCloudLocation, EnvGoogleCloudLocation
	}
	if t.Location == "" {
		t.Location, t.LocationFrom = DefaultGoogleCloudLocation, "default"
	}
	return t, true
}

// Candidate is one model the benchmark evaluates.
type Candidate struct {
	Name, Provider, Model string
	Roles                 []bench.Role
	// Current is the roles this candidate is the baseline of; a subset of Roles.
	Current []bench.Role
}

// Loaded is a validated configuration.
type Loaded struct {
	MaxUSD     pricing.NanoUSD
	MaxUSDRaw  string
	Plan       bench.Plan
	Candidates []Candidate
	Env        Env
}

type file struct {
	MaxUSD *string `toml:"max_usd"`
	Plan   *struct {
		Trials          *int    `toml:"trials"`
		TrialCapUSD     *string `toml:"trial_cap_usd"`
		MaxOutputTokens *int    `toml:"max_output_tokens"`
		Concurrency     *int    `toml:"concurrency"`
	} `toml:"plan"`
	Candidates []struct {
		Name     string   `toml:"name"`
		Provider string   `toml:"provider"`
		Model    string   `toml:"model"`
		Roles    []string `toml:"roles"`
		Current  []string `toml:"current"`
	} `toml:"candidates"`
}

// candidateName keeps a name usable as a path segment of a trial key and a trace directory.
var candidateName = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)

// Load reads the configuration at path, with env the values the CLI read from its flags and the
// environment.
func Load(path string, env Env, prices pricing.Table) (*Loaded, error) {
	var f file
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to read the configuration", goerr.V("config", path))
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, goerr.New("the configuration has keys this tool does not know", goerr.V("config", path), goerr.V("keys", keys))
	}

	out := &Loaded{MaxUSDRaw: DefaultMaxUSD, Plan: bench.DefaultPlan, Env: env}
	if f.MaxUSD != nil {
		out.MaxUSDRaw = *f.MaxUSD
	}
	if out.MaxUSD, err = pricing.ParseUSD(out.MaxUSDRaw); err != nil {
		return nil, goerr.Wrap(err, "max_usd is not a dollar amount", goerr.V("max_usd", out.MaxUSDRaw))
	}
	if out.MaxUSD <= 0 {
		return nil, goerr.New("max_usd must be more than zero", goerr.V("max_usd", out.MaxUSDRaw))
	}
	if p := f.Plan; p != nil {
		for _, v := range []struct {
			from *int
			to   *int
		}{{p.Trials, &out.Plan.Trials}, {p.MaxOutputTokens, &out.Plan.MaxOutputTokens}, {p.Concurrency, &out.Plan.Concurrency}} {
			if v.from != nil {
				*v.to = *v.from
			}
		}
		if p.TrialCapUSD != nil {
			if out.Plan.TrialCapUSD, err = pricing.ParseUSD(*p.TrialCapUSD); err != nil {
				return nil, goerr.Wrap(err, "trial_cap_usd is not a dollar amount", goerr.V("trial_cap_usd", *p.TrialCapUSD))
			}
		}
	}
	if err := out.Plan.Validate(); err != nil {
		return nil, err
	}

	if len(f.Candidates) == 0 {
		return nil, goerr.New("the configuration names no candidate", goerr.V("config", path))
	}
	seen := map[string]bool{}
	for _, c := range f.Candidates {
		if !candidateName.MatchString(c.Name) || seen[c.Name] {
			return nil, goerr.New("every candidate needs a name of its own, of letters, digits and . _ @ -",
				goerr.V("candidate", c.Name))
		}
		seen[c.Name] = true
		if err := checkProvider(c.Name, c.Provider, env); err != nil {
			return nil, err
		}
		if _, ok := prices.RateOf(c.Model); !ok {
			return nil, goerr.New("a candidate's model has no price, so its cost cannot be forecast",
				goerr.V("candidate", c.Name), goerr.V("model", c.Model))
		}
		roles, err := parseRoles(c.Name, c.Roles)
		if err != nil {
			return nil, err
		}
		if len(roles) == 0 {
			roles = slices.Clone(bench.Roles)
		}
		current, err := parseRoles(c.Name, c.Current)
		if err != nil {
			return nil, err
		}
		for _, r := range current {
			if !slices.Contains(roles, r) {
				return nil, goerr.New("a candidate is named the baseline of a role it is not evaluated on",
					goerr.V("candidate", c.Name), goerr.V("role", string(r)), goerr.V("roles", roles))
			}
		}
		out.Candidates = append(out.Candidates, Candidate{Name: c.Name, Provider: c.Provider, Model: c.Model, Roles: roles, Current: current})
	}
	return out, nil
}

// checkProvider refuses a candidate whose provider is unknown or cannot be called with env.
func checkProvider(name, provider string, env Env) error {
	switch provider {
	case ProviderGemini, ProviderClaudeVertex:
		t, _ := env.TargetFor(provider)
		if t.Project == "" {
			own := EnvGeminiProject
			if provider == ProviderClaudeVertex {
				own = EnvClaudeVertexProject
			}
			return goerr.New("an Agent Platform candidate needs a Google Cloud project: set "+own+" or "+EnvGoogleCloudProject,
				goerr.V("candidate", name), goerr.V("provider", provider))
		}
		// The price table holds the global endpoint's prices; multi-region and regional endpoints
		// cost 10% more.
		if provider == ProviderClaudeVertex && t.Location != DefaultGoogleCloudLocation {
			return goerr.New("a claude-vertex candidate runs on the global endpoint only: the price table holds the global "+
				"endpoint's prices, and multi-region and regional endpoints cost 10% more",
				goerr.V("candidate", name), goerr.V("location", t.Location), goerr.V("location_from", t.LocationFrom))
		}
	case ProviderClaude:
		if env.AnthropicAPIKey == "" {
			return goerr.New("a claude candidate needs an API key: set "+EnvAnthropicAPIKey, goerr.V("candidate", name))
		}
	case ProviderOpenAI:
		if env.OpenAIAPIKey == "" {
			return goerr.New("an openai candidate needs an API key: set "+EnvOpenAIAPIKey, goerr.V("candidate", name))
		}
	default:
		return goerr.New("a candidate names an unknown provider", goerr.V("candidate", name), goerr.V("provider", provider),
			goerr.V("providers", []string{ProviderGemini, ProviderClaudeVertex, ProviderClaude, ProviderOpenAI}))
	}
	return nil
}

// parseRoles reads role names, dropping repeats.
func parseRoles(candidate string, names []string) ([]bench.Role, error) {
	var out []bench.Role
	for _, n := range names {
		r := bench.Role(strings.TrimSpace(n))
		if !r.Valid() {
			return nil, goerr.New("a candidate names an unknown role", goerr.V("candidate", candidate), goerr.V("role", n),
				goerr.V("roles", bench.Roles))
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}
