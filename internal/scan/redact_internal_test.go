package scan

import (
	"strings"
	"testing"
)

func TestRedact_ShortSecretUsesFingerprint(t *testing.T) {
	// 20 chars: 8/20 = 40% exposure without fingerprint — must use fingerprint.
	got := redact("AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("short secret: expected sha256 fingerprint, got %q", got)
	}
	if strings.Contains(got, "AKIA") || strings.Contains(got, "MPLE") {
		t.Error("short secret: fingerprint must not contain raw chars")
	}
}

func TestRedact_LongSecretUsesMask(t *testing.T) {
	// 40 chars: 8/40 = 20% exposure — first4/last4 is acceptable.
	got := redact("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if !strings.ContainsRune(got, '*') {
		t.Errorf("long secret: expected stars in mask, got %q", got)
	}
	if strings.HasPrefix(got, "sha256:") {
		t.Errorf("long secret: must not use fingerprint, got %q", got)
	}
	// First 4 and last 4 chars of the original are present.
	if !strings.HasPrefix(got, "wJal") {
		t.Errorf("long secret: expected first4 prefix, got %q", got)
	}
	if !strings.HasSuffix(got, "EKEY") {
		t.Errorf("long secret: expected last4 suffix, got %q", got)
	}
}

func TestRedact_EmptyString(t *testing.T) {
	got := redact("")
	if got != "" {
		t.Errorf("empty: expected empty, got %q", got)
	}
}

func TestRedact_BoundaryAt24(t *testing.T) {
	// Exactly 24 chars: 8/24 = 33% — borderline, uses first4/last4.
	secret := "123456789012345678901234" // 24 chars
	got := redact(secret)
	if !strings.ContainsRune(got, '*') {
		t.Errorf("24-char secret: expected mask, got %q", got)
	}

	// 23 chars: uses fingerprint.
	secret23 := "12345678901234567890123"
	got23 := redact(secret23)
	if !strings.HasPrefix(got23, "sha256:") {
		t.Errorf("23-char secret: expected fingerprint, got %q", got23)
	}
}
