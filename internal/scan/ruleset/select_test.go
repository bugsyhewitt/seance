package ruleset

import (
	"reflect"
	"testing"
)

// fixtureRules returns a small, stable ruleset used across the Select tests.
func fixtureRules() []Rule {
	return []Rule{
		{ID: "aws-access-key-id"},
		{ID: "github-pat"},
		{ID: "generic-api-key"},
		{ID: "stripe-secret-key"},
	}
}

// ids extracts the rule IDs from a slice in order, for compact assertions.
func ids(rules []Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID
	}
	return out
}

// TestSelect_NoSelectionReturnsInput verifies the opt-in contract: with neither
// enable nor disable set, Select returns the input unchanged (same length, same
// order, same IDs) so the default behaviour is byte-for-byte the prior one.
func TestSelect_NoSelectionReturnsInput(t *testing.T) {
	in := fixtureRules()
	got := Select(in, nil, nil)
	if want := ids(in); !reflect.DeepEqual(ids(got), want) {
		t.Errorf("no selection: got IDs %v, want %v", ids(got), want)
	}
	// Empty (non-nil) slices must behave identically to nil.
	got = Select(in, []string{}, []string{})
	if want := ids(in); !reflect.DeepEqual(ids(got), want) {
		t.Errorf("empty slices: got IDs %v, want %v", ids(got), want)
	}
	// Blank-only entries are ignored and count as "no selection".
	got = Select(in, []string{"", "  "}, []string{" "})
	if want := ids(in); !reflect.DeepEqual(ids(got), want) {
		t.Errorf("blank-only selection: got IDs %v, want %v", ids(got), want)
	}
}

// TestSelect_EnableIsAllowlist verifies that a non-empty enable list keeps ONLY
// the listed rules, dropping every other rule, while preserving order.
func TestSelect_EnableIsAllowlist(t *testing.T) {
	got := Select(fixtureRules(), []string{"github-pat", "stripe-secret-key"}, nil)
	want := []string{"github-pat", "stripe-secret-key"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Errorf("enable allowlist: got %v, want %v", ids(got), want)
	}
}

// TestSelect_DisableIsDenylist verifies that a disable list removes the listed
// rules and leaves the rest in original order.
func TestSelect_DisableIsDenylist(t *testing.T) {
	got := Select(fixtureRules(), nil, []string{"generic-api-key"})
	want := []string{"aws-access-key-id", "github-pat", "stripe-secret-key"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Errorf("disable denylist: got %v, want %v", ids(got), want)
	}
}

// TestSelect_DisableWinsOverEnable verifies that a rule listed in BOTH enable
// and disable is dropped — disable always wins (gitleaks semantics).
func TestSelect_DisableWinsOverEnable(t *testing.T) {
	got := Select(fixtureRules(),
		[]string{"github-pat", "generic-api-key"},
		[]string{"generic-api-key"})
	want := []string{"github-pat"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Errorf("disable-over-enable: got %v, want %v", ids(got), want)
	}
}

// TestSelect_CaseInsensitive verifies that rule-ID matching ignores case on both
// the enable and disable axes.
func TestSelect_CaseInsensitive(t *testing.T) {
	got := Select(fixtureRules(), []string{"GitHub-PAT", "AWS-Access-Key-ID"}, []string{"GITHUB-pat"})
	want := []string{"aws-access-key-id"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Errorf("case-insensitive selection: got %v, want %v", ids(got), want)
	}
}

// TestSelect_UnknownIDsAreNoOps verifies that listing IDs that match no rule
// neither errors nor affects the result (enable of unknowns yields nothing;
// disable of unknowns drops nothing).
func TestSelect_UnknownIDsAreNoOps(t *testing.T) {
	// Disable of an unknown ID changes nothing.
	got := Select(fixtureRules(), nil, []string{"does-not-exist"})
	if want := ids(fixtureRules()); !reflect.DeepEqual(ids(got), want) {
		t.Errorf("disable unknown: got %v, want %v", ids(got), want)
	}
	// Enable of only-unknown IDs yields an empty set (allowlist matched nothing).
	got = Select(fixtureRules(), []string{"does-not-exist"}, nil)
	if len(got) != 0 {
		t.Errorf("enable unknown-only: got %v, want empty", ids(got))
	}
}

// TestSelect_DoesNotMutateInput verifies Select treats its input as read-only:
// the caller's slice and rule values are unchanged after a selection.
func TestSelect_DoesNotMutateInput(t *testing.T) {
	in := fixtureRules()
	before := ids(in)
	_ = Select(in, []string{"github-pat"}, []string{"aws-access-key-id"})
	if after := ids(in); !reflect.DeepEqual(after, before) {
		t.Errorf("input mutated: before %v, after %v", before, after)
	}
}

// TestSelect_TrimsWhitespace verifies surrounding whitespace on flag entries is
// trimmed before matching, so "--disable-rule ' github-pat '" still matches.
func TestSelect_TrimsWhitespace(t *testing.T) {
	got := Select(fixtureRules(), nil, []string{"  github-pat  "})
	want := []string{"aws-access-key-id", "generic-api-key", "stripe-secret-key"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Errorf("whitespace-trimmed disable: got %v, want %v", ids(got), want)
	}
}
