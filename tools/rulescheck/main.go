// Command rulescheck checks that every rule in docs/rules.txt whose milestone is done has
// a test named after its ID, and that every test named after an ID refers to a real rule.
// See the Test Strategy spec, section "Rule traceability".
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
)

var (
	idRe        = regexp.MustCompile(`^[RS][0-9]+\.[0-9]+$`)
	milestoneRe = regexp.MustCompile(`^M[0-9]+$`)
	testNameRe  = regexp.MustCompile(`(?m)^func (?:Test|Fuzz|Benchmark)([RS][0-9]+)_([0-9]+)_\w*\(`)
	verifiers   = map[string]bool{"test": true, "manual": true, "lint": true, "release": true}
)

type rule struct {
	ID, Milestone string
	Verified      []string
}

func (r rule) needsTest() bool { return slices.Contains(r.Verified, "test") }

// parseRules reads the rules file. It returns the rules in file order and the set of
// milestones listed on the "# done:" line.
func parseRules(r io.Reader) ([]rule, map[string]bool, error) {
	var (
		rules  []rule
		done   = map[string]bool{}
		seen   = map[string]bool{}
		header bool
		lineNo int
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "# done:"); ok {
			for m := range strings.FieldsSeq(rest) {
				if !milestoneRe.MatchString(m) {
					return nil, nil, fmt.Errorf("line %d: bad milestone %q on done line", lineNo, m)
				}
				done[m] = true
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !header {
			if line != "id,milestone,verified_by" {
				return nil, nil, fmt.Errorf("line %d: want header id,milestone,verified_by, got %q", lineNo, line)
			}
			header = true
			continue
		}
		f := strings.Split(line, ",")
		if len(f) != 3 {
			return nil, nil, fmt.Errorf("line %d: want 3 fields, got %d", lineNo, len(f))
		}
		ru := rule{ID: f[0], Milestone: f[1], Verified: strings.Split(f[2], "+")}
		if !idRe.MatchString(ru.ID) {
			return nil, nil, fmt.Errorf("line %d: bad rule id %q", lineNo, ru.ID)
		}
		if seen[ru.ID] {
			return nil, nil, fmt.Errorf("line %d: duplicate rule id %s", lineNo, ru.ID)
		}
		seen[ru.ID] = true
		if !milestoneRe.MatchString(ru.Milestone) {
			return nil, nil, fmt.Errorf("line %d: bad milestone %q", lineNo, ru.Milestone)
		}
		for _, v := range ru.Verified {
			if !verifiers[v] {
				return nil, nil, fmt.Errorf("line %d: unknown verified_by %q", lineNo, v)
			}
		}
		rules = append(rules, ru)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if !header {
		return nil, nil, fmt.Errorf("no header line found")
	}
	return rules, done, nil
}

// testedIDs maps each rule ID named by a test function in the tree to the files naming it.
// Reads go through fsys (an os.Root in main), so they cannot leave the repo.
func testedIDs(fsys fs.FS) (map[string][]string, error) {
	ids := map[string][]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "spike", "testdata", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		for _, m := range testNameRe.FindAllStringSubmatch(string(b), -1) {
			id := m[1] + "." + m[2]
			ids[id] = append(ids[id], path)
		}
		return nil
	})
	return ids, err
}

// check returns one problem per line; empty means everything is consistent.
func check(rules []rule, done map[string]bool, tested map[string][]string) []string {
	var problems []string
	known := map[string]bool{}
	for _, r := range rules {
		known[r.ID] = true
		if done[r.Milestone] && r.needsTest() && len(tested[r.ID]) == 0 {
			problems = append(problems, fmt.Sprintf("%s (%s, done) has no test named Test%s_...",
				r.ID, r.Milestone, strings.Replace(r.ID, ".", "_", 1)))
		}
	}
	for id, files := range tested {
		if !known[id] {
			problems = append(problems, fmt.Sprintf("%s is named by a test in %s but is not in docs/rules.txt",
				id, strings.Join(files, ", ")))
		}
	}
	sort.Strings(problems)
	return problems
}

func run(dir string, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		_, _ = fmt.Fprintf(stderr, "rulescheck: "+format+"\n", args...)
		return 1
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail("%v", err)
	}
	defer func() { _ = root.Close() }()
	fsys := root.FS()

	b, err := fs.ReadFile(fsys, "docs/rules.txt")
	if err != nil {
		return fail("%v", err)
	}
	rules, done, err := parseRules(bytes.NewReader(b))
	if err != nil {
		return fail("docs/rules.txt: %v", err)
	}
	tested, err := testedIDs(fsys)
	if err != nil {
		return fail("%v", err)
	}
	if problems := check(rules, done, tested); len(problems) > 0 {
		for _, p := range problems {
			fail("%s", p)
		}
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "rulescheck: %d rules, %d named by tests, done milestones: %s\n",
		len(rules), len(tested), doneList(done))
	return 0
}

func doneList(done map[string]bool) string {
	if len(done) == 0 {
		return "none"
	}
	ms := make([]string, 0, len(done))
	for m := range done {
		ms = append(ms, m)
	}
	sort.Strings(ms)
	return strings.Join(ms, " ")
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	os.Exit(run(root, os.Stdout, os.Stderr))
}
