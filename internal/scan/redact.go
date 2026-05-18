package scan

import (
	"crypto/sha256"
	"fmt"
)

// minRevealLen is the minimum secret length at which first4/last4 exposure is
// acceptable. Below this, first4+last4 would reveal >= 1/3 of the raw value,
// violating the "never create a new leak" invariant.
// At exactly minRevealLen (24): 8/24 = 33% revealed — borderline acceptable.
// Below 24: fingerprint instead.
const minRevealLen = 24

// redact returns a masked representation of a matched secret value.
// For short secrets (< 24 chars), exposing first4+last4 would reveal more than
// a third of the raw material, so a stable SHA-256 fingerprint is returned
// instead — sufficient for the owner to identify which credential leaked.
// Raw secret material is discarded after this function returns.
func redact(s string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) < minRevealLen {
		h := sha256.Sum256([]byte(s))
		return fmt.Sprintf("sha256:%x", h[:4]) // 8 hex chars, 32 bits
	}
	const stars = "********************"
	return s[:4] + stars + s[len(s)-4:]
}

// RedactedFingerprint returns the same fingerprint that redact() uses for
// short secrets, so callers can verify a known value matches a finding.
func RedactedFingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x", h[:4])
}
