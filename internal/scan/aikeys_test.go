package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// These tests exercise the AI/LLM-provider rules (openai-api-key,
// anthropic-api-key, huggingface-access-token) through the REAL shipped
// signatures/default.toml and the real engine — not a hand-built rule slice.
// AI provider keys are the fastest-growing class of leaked credential in the
// 2024–2026 landscape and seance previously had zero coverage. The default
// ruleset had only a structural-validation test (TestValidate_DefaultRulesetIsClean);
// this adds the first behavioral coverage for it. Every synthetic token below is
// fabricated: it matches the issuer's documented prefix shape but is not a live
// credential, carries enough entropy to clear the 3.5 gate, and avoids the global
// placeholder filter (no 8-char mono-runs, no placeholder words).

// loadDefaultRules loads the shipped default ruleset for engine-level tests.
func loadDefaultRules(t *testing.T) []ruleset.Rule {
	t.Helper()
	rs, err := ruleset.LoadFile("../../signatures/default.toml")
	if err != nil {
		t.Fatalf("load default ruleset: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("default ruleset is empty")
	}
	return rs.Rules
}

// scanLine runs the default ruleset over a single line and returns the findings.
func scanLine(t *testing.T, line string) []output.Finding {
	t.Helper()
	var findings []output.Finding
	engine := scan.New(loadDefaultRules(t), &captureSink{findings: &findings})
	if _, err := engine.Scan(context.Background(), newContent(line, []string{line})); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return findings
}

// openAIProjectKey assembles a fabricated OpenAI project-key fixture from
// fragments at runtime. The literal `sk-proj-…T3BlbkFJ…` sequence is GitHub
// secret-scanning's own match shape, so building it from parts keeps the
// (entirely fake) test data from tripping push protection while still matching
// seance's openai-api-key rule. body must be high-entropy base62.
func openAIProjectKey(bodyA, bodyB string) string {
	return "sk-" + "proj-" + bodyA + "T3Blbk" + "FJ" + bodyB
}

// findByRule returns the first finding produced by ruleID, or false.
func findByRule(findings []output.Finding, ruleID string) (output.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return output.Finding{}, false
}

func TestDefaultRuleset_DetectsOpenAIProjectKey(t *testing.T) {
	// Modern OpenAI project key shape: sk-proj-<seg>T3BlbkFJ<seg>. Assembled from
	// fragments so the fake fixture does not trip GitHub push protection.
	secret := openAIProjectKey("Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0", "aZ2bX4cV6nM8kQ1wE3rT5yU7iO9")
	line := "OPENAI_API_KEY=" + secret
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "openai-api-key")
	if !ok {
		t.Fatalf("openai project key not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw key")
	}
}

func TestDefaultRuleset_DetectsOpenAILegacyKey(t *testing.T) {
	// Legacy fixed-length OpenAI key shape: sk- + 48 chars. Assembled from
	// fragments so the fake fixture does not trip GitHub push protection.
	secret := "sk-" + "Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX4cV6nM8kQ1wEr"
	line := `openai_key = "` + secret + `"`
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "openai-api-key"); !ok {
		t.Fatalf("legacy openai key not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DetectsAnthropicKey(t *testing.T) {
	// Anthropic key shape: sk-ant-api03-<~95 chars>.
	secret := "sk-ant-api03-Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX4cV6nM8kQ1wE3rT5yU7iO9pL2dG4hJ6kS8mN0qW2eR4tY6uI8oP0aA"
	line := "ANTHROPIC_API_KEY=" + secret
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "anthropic-api-key")
	if !ok {
		t.Fatalf("anthropic key not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw key")
	}
}

func TestDefaultRuleset_DetectsHuggingFaceToken(t *testing.T) {
	// Hugging Face token shape: hf_ + 34+ alphanumerics.
	secret := "hf_Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX"
	line := "HUGGINGFACE_TOKEN=" + secret
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "huggingface-access-token"); !ok {
		t.Fatalf("hugging face token not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_OpenAIPlaceholderSuppressed(t *testing.T) {
	// A documentation stand-in carrying a placeholder word must be dropped by the
	// global placeholder filter even though it matches the prefix shape.
	line := "OPENAI_API_KEY=" + openAIProjectKey("your_api_key_here", "your_api_key_here")
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "openai-api-key"); ok {
		t.Errorf("placeholder openai key must not be reported; findings=%+v", findings)
	}
}

func TestDefaultRuleset_AIKeysNoFalsePositiveOnProse(t *testing.T) {
	// Ordinary prose mentioning these providers must not trip any AI rule.
	line := "We use the OpenAI and Anthropic and Hugging Face APIs in production."
	findings := scanLine(t, line)
	for _, ruleID := range []string{"openai-api-key", "anthropic-api-key", "huggingface-access-token"} {
		if _, ok := findByRule(findings, ruleID); ok {
			t.Errorf("rule %q false-positived on prose; findings=%+v", ruleID, findings)
		}
	}
}
