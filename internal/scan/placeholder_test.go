package scan

import "testing"

// TestIsPlaceholder_Tokens verifies that values carrying a known placeholder
// word are flagged, regardless of case.
func TestIsPlaceholder_Tokens(t *testing.T) {
	cases := []string{
		"AKIAIOSFODNN7EXAMPLE",                     // AWS documented sample key
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // AWS documented sample secret
		"your_api_key_here",
		"YOUR-SECRET-VALUE",
		"changeme",
		"INSERT_KEY_HERE",
		"placeholderToken123456789012",
		"a-dummy_key-value",
		"a_redacted_token_value", // carries the "redacted" placeholder word
		"loremipsumdolorsitamet",
		"0123456789abcdef0123456789abcdef",
		"theQuickabcdefghijklmnopqrstuvwxyzJumps",
	}
	for _, c := range cases {
		if !isPlaceholder(c) {
			t.Errorf("isPlaceholder(%q) = false, want true", c)
		}
	}
}

// TestIsPlaceholder_MonoRuns verifies that long single-character runs (manual
// masks) are flagged.
func TestIsPlaceholder_MonoRuns(t *testing.T) {
	cases := []string{
		"AKIAAAAAAAAAAAAAAAAA",                     // 16 A's after AKIA
		"ghp_000000000000000000000000000000000000", // zero-mask
		"xxxxxxxxxxxxxxxx",                         // 16 x's (also matches token)
		"abcd11111111efgh",                         // 8 ones in the middle
	}
	for _, c := range cases {
		if !isPlaceholder(c) {
			t.Errorf("isPlaceholder(%q) = false, want true", c)
		}
	}
}

// TestIsPlaceholder_RealKeysPass verifies that plausibly-real, randomly
// generated credentials are NOT flagged — the conservative invariant: a real
// leak must never be suppressed.
func TestIsPlaceholder_RealKeysPass(t *testing.T) {
	cases := []string{
		"AKIA2E4F6H8J0L2N4P6R",                     // realistic AWS access key id
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYz9q8s3T1uV", // realistic AWS secret
		"ghp_x7Kp2mQ9vR4nT8wL3jF6dH1sB5cN0aZ9eYqW", // realistic GitHub PAT
		"q3Wp7nT2vK8mL4jF9dH6sB1cR5xZ0aN",  // realistic high-entropy token
		"r8Kp2mQ9vR4nT8wL3jF6dH1sB5cN0aZ9", // realistic high-entropy token
		"",                                         // empty → not a placeholder
		"aaaaaaa",                                  // 7 a's: below the 8-run threshold, passes
	}
	for _, c := range cases {
		if isPlaceholder(c) {
			t.Errorf("isPlaceholder(%q) = true, want false (must not suppress real keys)", c)
		}
	}
}

// TestHasLongMonoRun_Threshold checks the exact boundary of the mono-run
// detector: a run of maxMonoRun-1 passes, maxMonoRun fails.
func TestHasLongMonoRun_Threshold(t *testing.T) {
	below := "z" + repeat('q', maxMonoRun-1) + "z" // 7-run
	if hasLongMonoRun(below) {
		t.Errorf("run of %d should be tolerated", maxMonoRun-1)
	}
	at := "z" + repeat('q', maxMonoRun) + "z" // 8-run
	if !hasLongMonoRun(at) {
		t.Errorf("run of %d should be flagged", maxMonoRun)
	}
	if hasLongMonoRun("short") {
		t.Error("string shorter than maxMonoRun must never flag")
	}
}

// TestRuleSkipsPlaceholderFilter verifies the per-rule opt-out tag.
func TestRuleSkipsPlaceholderFilter(t *testing.T) {
	if !ruleSkipsPlaceholderFilter([]string{"generic", noPlaceholderFilterTag}) {
		t.Error("rule tagged no-placeholder-filter should opt out")
	}
	if ruleSkipsPlaceholderFilter([]string{"generic", "aws"}) {
		t.Error("rule without the tag should not opt out")
	}
	if ruleSkipsPlaceholderFilter(nil) {
		t.Error("nil tags should not opt out")
	}
}

func repeat(c rune, n int) string {
	r := make([]rune, n)
	for i := range r {
		r[i] = c
	}
	return string(r)
}
