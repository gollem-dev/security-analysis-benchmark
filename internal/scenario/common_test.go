package scenario_test

import (
	"testing"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/scenario"
)

func TestStatedIdentifiersFindAddressesByTheirShape(t *testing.T) {
	gt.A(t, scenario.StatedIdentifiers("see bob@example.com. and 10.2.3.44", nil)).Equal([]string{"bob@example.com", "10.2.3.44"})
	gt.A(t, scenario.StatedIdentifiers("Seen: Bob@Example.com from 10.0.0.7, and d-0042.", []string{"D-0042", "D-0099"})).
		Equal([]string{"D-0042", "Bob@Example.com", "10.0.0.7"})
}

func TestANumberIsStatedWhateverFollowsItButADigit(t *testing.T) {
	gt.B(t, scenario.StatesValue("5 files", "5")).True()
	gt.B(t, scenario.StatesValue("5x", "5")).True()
	gt.B(t, scenario.StatesValue("15 files", "5")).False()
	gt.B(t, scenario.StatesValue("50 files", "5")).False()
	// Any other value stands as a word.
	gt.B(t, scenario.StatesValue("macos 15.4", "15.4")).True()
	gt.B(t, scenario.StatesValue("d-00421", "d-0042")).False()
	gt.B(t, scenario.StatesValue("\"d-0042\"", "d-0042")).True()
}
