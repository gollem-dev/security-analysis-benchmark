package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode"

	"github.com/m-mizutani/gt"
)

// Everything committed to this repository is written in English only.
func TestNoCommittedFileHoldsJapanese(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skip("git cannot list the repository's files: " + err.Error())
	}
	var found []string
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		raw, err := os.ReadFile(name) // #nosec G304 -- the repository's own files
		if name == "" || err != nil {
			continue // a file listed but removed from the working tree
		}
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
		for n := 1; scanner.Scan(); n++ {
			if line := scanner.Text(); strings.ContainsFunc(line, japanese) {
				found = append(found, fmt.Sprintf("%s:%d: %s", name, n, line))
			}
		}
	}
	for _, f := range found {
		t.Log(f)
	}
	gt.A(t, found).Length(0)
}

// japanese reports whether r is a kana, a kanji, or a CJK or full-width punctuation mark.
func japanese(r rune) bool {
	return unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) ||
		(r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF)
}
