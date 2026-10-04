// Package pricing holds what each model costs per token and does the money arithmetic in whole
// nano-dollars, so that no amount is ever rounded until it is shown.
package pricing

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/m-mizutani/goerr/v2"
)

// NanoUSD is an amount of money in nano-dollars (10^-9 USD).
type NanoUSD int64

const nanoPerUSD = 1_000_000_000

// USD formats the amount to the cent, cutting off what is below it: "$1.23".
func (n NanoUSD) USD() string {
	return format(n, 2, false)
}

// USD4 formats the amount to four places, rounding half up: "$1.2346".
func (n NanoUSD) USD4() string {
	return format(n, 4, true)
}

func format(n NanoUSD, places int, round bool) string {
	sign := ""
	// Unsigned, so that the most negative amount is not negated into itself.
	mag := uint64(n) // #nosec G115 -- replaced below when n is negative
	if n < 0 {
		sign = "-"
		mag = uint64(-(n + 1)) + 1 // #nosec G115 -- -(n+1) of a negative n is never negative
	}
	unit := uint64(1)
	for range 9 - places {
		unit *= 10
	}
	units := mag / unit
	if round && mag%unit >= unit/2 {
		units++
	}
	scale := uint64(1)
	for range places {
		scale *= 10
	}
	return fmt.Sprintf("%s$%d.%0*d", sign, units/scale, places, units%scale)
}

// ParseUSD reads a dollar amount written in decimal, with at most nine places and no sign, currency
// symbol or exponent: "30.00", "0.000000001", "2".
func ParseUSD(s string) (NanoUSD, error) {
	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" || (hasFrac && frac == "") || len(frac) > 9 || !digits(whole) || !digits(frac) {
		return 0, goerr.New("not a dollar amount: write it in decimal with at most nine places",
			goerr.V("value", s))
	}
	var w int64
	for _, c := range whole {
		if w > (1<<63-1)/10/nanoPerUSD {
			return 0, goerr.New("the dollar amount is too large", goerr.V("value", s))
		}
		w = w*10 + int64(c-'0')
	}
	f := frac + strings.Repeat("0", 9-len(frac))
	var n int64
	for _, c := range f {
		n = n*10 + int64(c-'0')
	}
	return NanoUSD(w*nanoPerUSD + n), nil
}

func digits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Rate is one model's price of one token, in nano-dollars.
type Rate struct {
	// Input is an input token read neither from nor into a cache.
	Input      NanoUSD `json:"input"`
	Output     NanoUSD `json:"output"`
	CacheRead  NanoUSD `json:"cache_read"`
	CacheWrite NanoUSD `json:"cache_write"`
}

// Cost is what one LLM call cost. input is every input token, the cached ones included, as the
// providers report it; the part neither read from nor written to a cache is priced as Input.
func (r Rate) Cost(input, output, cacheRead, cacheWrite int64) NanoUSD {
	uncached := max(input-cacheRead-cacheWrite, 0)
	return NanoUSD(uncached)*r.Input + NanoUSD(cacheRead)*r.CacheRead +
		NanoUSD(cacheWrite)*r.CacheWrite + NanoUSD(output)*r.Output
}

//go:embed prices.json
var pricesJSON []byte

type entry struct {
	Rate
	Source  string `json:"source"`
	Checked string `json:"checked"`
}

// Table is the price of every model this build knows.
type Table struct{ rates map[string]Rate }

// Embedded is the price table built into the binary. A model priced at zero for its input or its
// output is refused: it would make every forecast and reservation of that model free.
func Embedded() (Table, error) {
	return parse(pricesJSON)
}

func parse(raw []byte) (Table, error) {
	var entries map[string]entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return Table{}, goerr.Wrap(err, "failed to decode the price table")
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	t := Table{rates: map[string]Rate{}}
	for _, name := range names {
		e := entries[name]
		if e.Input <= 0 || e.Output <= 0 {
			return Table{}, goerr.New("a model in the price table has no input or output price",
				goerr.V("model", name), goerr.V("input", int64(e.Input)), goerr.V("output", int64(e.Output)))
		}
		t.rates[name] = e.Rate
	}
	return t, nil
}

// RateOf is the model's price, and false when the table has none.
func (t Table) RateOf(model string) (Rate, bool) {
	r, ok := t.rates[model]
	return r, ok
}
