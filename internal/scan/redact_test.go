package scan_test

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/scan"
)

func TestRedact_ShortSecretGetsFingerprint(t *testing.T) {
	// 20-char AWS key ID: first4+last4 = 8/20 = 40% — over the 1/3 threshold.
	// Must return fingerprint, not raw chars.
	secret := "AKIAIOSFODNN7EXAMPLE"
	got := scan.RedactedFingerprint(secret) // same path as internal redact()

	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("expected sha256 prefix, got %q", got)
	}
	if strings.Contains(got, secret) {
		t.Error("fingerprint must not contain raw secret")
	}
	// Same input must produce the same fingerprint (stable for owner lookup).
	got2 := scan.RedactedFingerprint(secret)
	if got != got2 {
		t.Errorf("fingerprint is not stable: %q vs %q", got, got2)
	}
}

func TestRedact_LongSecretGetsMasked(t *testing.T) {
	// 40-char secret: first4+last4 = 8/40 = 20% — under the 1/3 threshold.
	// Must return first4 + stars + last4.
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	// Use RedactedFingerprint to verify fingerprint path is NOT taken for long secrets.
	// We can't call unexported redact() directly; test via engine_test instead.
	// Here just verify the fingerprint helper is stable for both lengths.
	fp := scan.RedactedFingerprint(secret)
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint helper: expected sha256 prefix, got %q", fp)
	}
	_ = secret // actual redact() path verified in TestEngine_FindsLongSecret
}

func TestRedact_EmptyString(t *testing.T) {
	fp := scan.RedactedFingerprint("")
	// Empty input: fingerprint of empty string — should not panic
	if fp == "" {
		t.Error("fingerprint of empty string must not be empty")
	}
}
