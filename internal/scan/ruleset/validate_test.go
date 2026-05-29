package ruleset

import (
	"strings"
	"testing"
)

// countSeverity returns how many problems carry the given severity.
func countSeverity(problems []Problem, severity string) int {
	n := 0
	for _, p := range problems {
		if p.Severity == severity {
			n++
		}
	}
	return n
}

// findProblem returns the first problem whose Field contains fieldSubstr, or a
// zero Problem and false if none match.
func findProblem(problems []Problem, fieldSubstr string) (Problem, bool) {
	for _, p := range problems {
		if strings.Contains(p.Field, fieldSubstr) {
			return p, true
		}
	}
	return Problem{}, false
}

func TestValidate_CleanRulesetHasNoProblems(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `AKIA[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
		},
		{
			ID:       "stripe-secret-key",
			Regex:    `sk_(?:live|test)_[0-9a-zA-Z]{24,}`,
			Keywords: []string{"sk_live_", "sk_test_"},
			Entropy:  3.5,
		},
	}}
	problems := Validate(rs)
	if len(problems) != 0 {
		t.Fatalf("clean ruleset should have no problems, got %d: %v", len(problems), problems)
	}
	if HasErrors(problems) {
		t.Error("clean ruleset should not report errors")
	}
}

func TestValidate_DefaultRulesetIsClean(t *testing.T) {
	// The shipped default ruleset must always validate clean — it is the
	// reference every operator copies from.
	rs, err := LoadFile("../../../signatures/default.toml")
	if err != nil {
		t.Fatalf("load default ruleset: %v", err)
	}
	problems := Validate(rs)
	if HasErrors(problems) {
		t.Fatalf("default ruleset must validate without errors, got: %v", problems)
	}
	if len(problems) != 0 {
		t.Errorf("default ruleset should be warning-free, got: %v", problems)
	}
}

func TestValidate_BadRegexIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "broken",
		Regex:    `AKIA[A-Z0-9{16}`, // unbalanced bracket
		Keywords: []string{"AKIA"},
	}}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Fatal("malformed regex must produce an error")
	}
	p, ok := findProblem(problems, "regex")
	if !ok {
		t.Fatalf("expected a regex problem, got %v", problems)
	}
	if p.Severity != SeverityError {
		t.Errorf("regex compile failure should be an error, got %q", p.Severity)
	}
	if p.RuleID != "broken" {
		t.Errorf("problem should attribute to rule id 'broken', got %q", p.RuleID)
	}
}

func TestValidate_EmptyRegexIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "no-regex",
		Regex:    "",
		Keywords: []string{"x"},
	}}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Fatal("empty regex must be an error")
	}
	if _, ok := findProblem(problems, "regex"); !ok {
		t.Errorf("expected a regex problem, got %v", problems)
	}
}

func TestValidate_MissingIDIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "  ", // whitespace only
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}}
	problems := Validate(rs)
	p, ok := findProblem(problems, "id")
	if !ok {
		t.Fatalf("expected an id problem, got %v", problems)
	}
	if p.Severity != SeverityError {
		t.Errorf("missing id should be an error, got %q", p.Severity)
	}
}

func TestValidate_DuplicateIDIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{
		{ID: "dup", Regex: `a`, Keywords: []string{"a"}},
		{ID: "dup", Regex: `b`, Keywords: []string{"b"}},
	}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Fatal("duplicate id must be an error")
	}
	// The error should attribute to the second occurrence (index 1).
	var found bool
	for _, p := range problems {
		if strings.Contains(p.Field, "id") && p.RuleIndex == 1 && p.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate-id error on the second rule, got %v", problems)
	}
}

func TestValidate_BadAllowlistRegexIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "al",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
		AllowList: AllowList{
			Regexes: []string{`EXAMPLE(`}, // unbalanced paren
		},
	}}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Fatal("malformed allowlist regex must be an error")
	}
	p, ok := findProblem(problems, "allowlist.regexes")
	if !ok {
		t.Fatalf("expected an allowlist.regexes problem, got %v", problems)
	}
	if p.Severity != SeverityError {
		t.Errorf("allowlist regex compile failure should be an error, got %q", p.Severity)
	}
}

func TestValidate_BadAllowlistPathIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "al",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
		AllowList: AllowList{
			Paths: []string{`test[`}, // unbalanced bracket
		},
	}}}
	problems := Validate(rs)
	if _, ok := findProblem(problems, "allowlist.paths"); !ok {
		t.Fatalf("expected an allowlist.paths problem, got %v", problems)
	}
	if !HasErrors(problems) {
		t.Error("malformed allowlist path must be an error")
	}
}

func TestValidate_StopwordsAndCommitsNeedNoCompilation(t *testing.T) {
	// stopwords and commits are literal/prefix matches, never compiled — a
	// regex-special character in them is not an error.
	rs := &Ruleset{Rules: []Rule{{
		ID:       "literal-allowlist",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
		AllowList: AllowList{
			StopWords: []string{"this(is)not[a]regex"},
			Commits:   []string{"deadbeef("},
		},
	}}}
	problems := Validate(rs)
	if HasErrors(problems) {
		t.Errorf("literal stopwords/commits should not error, got %v", problems)
	}
}

func TestValidate_SecretGroupOutOfRangeIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:          "sg",
		Regex:       `(AKIA)[A-Z0-9]{16}`, // 1 capture group
		Keywords:    []string{"AKIA"},
		SecretGroup: 3, // out of range
	}}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Fatal("out-of-range secretGroup must be an error")
	}
	if _, ok := findProblem(problems, "secretGroup"); !ok {
		t.Errorf("expected a secretGroup problem, got %v", problems)
	}
}

func TestValidate_SecretGroupInRangeIsClean(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:          "sg-ok",
		Regex:       `(AKIA)([A-Z0-9]{16})`, // 2 capture groups
		Keywords:    []string{"AKIA"},
		SecretGroup: 2,
	}}}
	problems := Validate(rs)
	if HasErrors(problems) {
		t.Errorf("in-range secretGroup should be clean, got %v", problems)
	}
}

func TestValidate_NegativeSecretGroupIsError(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:          "neg",
		Regex:       `AKIA[A-Z0-9]{16}`,
		Keywords:    []string{"AKIA"},
		SecretGroup: -1,
	}}}
	problems := Validate(rs)
	if !HasErrors(problems) {
		t.Error("negative secretGroup must be an error")
	}
}

func TestValidate_MissingKeywordsIsWarning(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:    "no-kw",
		Regex: `AKIA[A-Z0-9]{16}`,
	}}}
	problems := Validate(rs)
	if HasErrors(problems) {
		t.Errorf("missing keywords alone should not be an error, got %v", problems)
	}
	p, ok := findProblem(problems, "keywords")
	if !ok {
		t.Fatalf("expected a keywords warning, got %v", problems)
	}
	if p.Severity != SeverityWarning {
		t.Errorf("missing keywords should be a warning, got %q", p.Severity)
	}
}

func TestValidate_ImplausibleEntropyIsWarning(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{
		ID:       "ent",
		Regex:    `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
		Entropy:  9.9, // impossible: > 8 bits/byte
	}}}
	problems := Validate(rs)
	p, ok := findProblem(problems, "entropy")
	if !ok {
		t.Fatalf("expected an entropy warning, got %v", problems)
	}
	if p.Severity != SeverityWarning {
		t.Errorf("implausible entropy should be a warning, got %q", p.Severity)
	}
}

func TestValidate_MultipleProblemsAreAllReported(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{
		{ID: "", Regex: `bad[`, Keywords: nil},                            // missing id + bad regex + no keywords
		{ID: "ok", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"}}, // clean
	}}
	problems := Validate(rs)
	if countSeverity(problems, SeverityError) < 2 {
		t.Errorf("expected at least 2 errors (missing id, bad regex), got %d: %v", countSeverity(problems, SeverityError), problems)
	}
	if countSeverity(problems, SeverityWarning) < 1 {
		t.Errorf("expected at least 1 warning (no keywords), got %d: %v", countSeverity(problems, SeverityWarning), problems)
	}
}

func TestValidate_ProblemsSortedByRuleIndex(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{
		{ID: "r0", Regex: `bad(`, Keywords: []string{"x"}},
		{ID: "r1", Regex: `also[`, Keywords: []string{"y"}},
	}}
	problems := Validate(rs)
	last := -1
	for _, p := range problems {
		if p.RuleIndex < last {
			t.Fatalf("problems not sorted by rule index: %v", problems)
		}
		last = p.RuleIndex
	}
}

func TestProblem_StringIncludesSeverityAndID(t *testing.T) {
	p := Problem{RuleID: "my-rule", RuleIndex: 2, Field: "regex", Severity: SeverityError, Message: "boom"}
	s := p.String()
	for _, want := range []string{"ERROR", "my-rule", "regex", "boom"} {
		if !strings.Contains(s, want) {
			t.Errorf("Problem.String() = %q, missing %q", s, want)
		}
	}
}

func TestProblem_StringForMissingIDUsesIndex(t *testing.T) {
	p := Problem{RuleID: "", RuleIndex: 4, Field: "id", Severity: SeverityError, Message: "no id"}
	s := p.String()
	if !strings.Contains(s, "rule #4") {
		t.Errorf("Problem.String() for unnamed rule should reference its index, got %q", s)
	}
}

func TestHasErrors(t *testing.T) {
	if HasErrors(nil) {
		t.Error("nil problems should report no errors")
	}
	if HasErrors([]Problem{{Severity: SeverityWarning}}) {
		t.Error("warnings-only should report no errors")
	}
	if !HasErrors([]Problem{{Severity: SeverityWarning}, {Severity: SeverityError}}) {
		t.Error("a single error among warnings should report errors")
	}
}
