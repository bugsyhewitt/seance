// Package output defines the Finding type and Sink interface for séance results.
//
// HARD INVARIANT: séance never stores raw secret values. Every Finding carries
// only a redacted representation of the matched string plus locator metadata
// sufficient for the owner to find and rotate the credential. This is not a
// default or a setting — it is an architectural invariant baked into the type.
package output

import (
	"context"
	"fmt"
	"time"
)

// Finding represents a detected potential secret. Raw secret material is
// intentionally absent — only the Redacted field is populated with a masked
// value (e.g. "AKIA********************WXYZ").
type Finding struct {
	RuleID     string    `json:"rule_id"`
	RuleDesc   string    `json:"rule_description,omitempty"`
	Provider   string    `json:"provider"`
	RepoOwner  string    `json:"repo_owner"`
	RepoName   string    `json:"repo_name"`
	CommitSHA  string    `json:"commit_sha"`
	FilePath   string    `json:"file_path"`
	LineNumber int       `json:"line_number"`
	Redacted   string    `json:"redacted"`   // masked value: first/last 4 chars + stars
	Confidence float64   `json:"confidence"` // 0.0–1.0
	Tags       []string  `json:"tags,omitempty"`
	Timestamp  time.Time `json:"timestamp"`

	// Fingerprint is a stable, privacy-preserving identifier for this finding,
	// derived only from redacted/locator fields (never raw secret bytes). It is
	// used for cross-run deduplication and is the value an operator copies into a
	// --suppress-file entry to silence a known false positive. Identical secrets
	// in the same location produce identical fingerprints, so re-leaks collide
	// correctly without ever touching raw material.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Sink receives Findings for output. Multiple Sinks may be composed.
type Sink interface {
	// Emit delivers a single Finding to this sink.
	Emit(ctx context.Context, finding Finding) error
	// Close flushes buffered output and releases resources.
	Close() error
}

// ValidateConfidence returns an error if v is outside [0.0, 1.0]. name is the
// sink or flag name included in the error message so the operator knows which
// field is invalid. Call it in each sink's New() to consolidate the range check.
func ValidateConfidence(name string, v float64) error {
	if v < 0 || v > 1 {
		return fmt.Errorf("%s: min-confidence must be between 0.0 and 1.0, got %.2f", name, v)
	}
	return nil
}
