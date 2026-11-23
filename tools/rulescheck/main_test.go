package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture sources are written with "\n" escapes, never raw multi-line strings, so this
// file does not itself contain lines that look like rule tests.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseRules(t *testing.T) {
	in := "# comment\n# done: M0 M1\n\nid,milestone,verified_by\nR1.1,M1,test\nS2.3,M2,test+lint\n"
	rules, done, err := parseRules(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[1].ID != "S2.3" || !rules[1].needsTest() {
		t.Fatalf("rules = %+v", rules)
	}
	if !done["M0"] || !done["M1"] || done["M2"] {
		t.Fatalf("done = %v", done)
	}
}

func TestParseRulesErrors(t *testing.T) {
	cases := map[string]string{
		"no header":       "R1.1,M1,test\n",
		"bad id":          "id,milestone,verified_by\nR1,M1,test\n",
		"duplicate":       "id,milestone,verified_by\nR1.1,M1,test\nR1.1,M1,test\n",
		"bad milestone":   "id,milestone,verified_by\nR1.1,one,test\n",
		"bad verifier":    "id,milestone,verified_by\nR1.1,M1,unit\n",
		"wrong field num": "id,milestone,verified_by\nR1.1,M1\n",
		"bad done":        "# done: first\nid,milestone,verified_by\n",
		"empty":           "",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRules(strings.NewReader(in)); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestCheck(t *testing.T) {
	rules := []rule{
		{ID: "R1.1", Milestone: "M1", Verified: []string{"test"}},
		{ID: "R1.2", Milestone: "M1", Verified: []string{"manual"}},
		{ID: "R2.1", Milestone: "M2", Verified: []string{"test"}},
	}
	done := map[string]bool{"M1": true}

	if p := check(rules, done, map[string][]string{"R1.1": {"a_test.go"}}); len(p) != 0 {
		t.Fatalf("want no problems, got %v", p)
	}

	p := check(rules, done, map[string][]string{"R9.9": {"b_test.go"}})
	if len(p) != 2 ||
		!strings.Contains(p[0], "R1.1 (M1, done) has no test") ||
		!strings.Contains(p[1], "R9.9 is named by a test in b_test.go") {
		t.Fatalf("problems = %v", p)
	}
}

func TestRunOnTree(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "docs", "rules.txt"), "# done: M1\nid,milestone,verified_by\nR4.2,M1,test\n")
	writeFile(t, filepath.Join(root, "internal", "x", "x_test.go"), "package x\n\nfunc TestR4_2_RestoresOnSignal(t *testing.T) {}\n")
	writeFile(t, filepath.Join(root, "spike", "s", "s_test.go"), "package s\n\nfunc TestR8_8_Ignored(t *testing.T) {}\n")

	var out, errb bytes.Buffer
	if code := run(root, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "1 rules, 1 named by tests, done milestones: M1") {
		t.Fatalf("stdout = %q", out.String())
	}

	writeFile(t, filepath.Join(root, "internal", "x", "x_test.go"), "package x\n")
	out.Reset()
	errb.Reset()
	if code := run(root, &out, &errb); code != 1 || !strings.Contains(errb.String(), "R4.2 (M1, done) has no test") {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
}
