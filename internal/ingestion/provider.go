// Package ingestion defines the core types and Provider interface for ingesting
// public commit events. Implementations are not required to expose a global
// event stream — some providers may only support targeted repository scanning.
package ingestion

import (
	"context"
	"time"
)

// CommitEvent represents a single commit observed from a provider.
// All fields are populated from the event payload; no extra API requests
// are needed to construct a CommitEvent.
type CommitEvent struct {
	Provider    string
	RepoOwner   string
	RepoName    string
	CommitSHA   string
	CommitMsg   string
	AuthorName  string
	AuthorEmail string
	Files       []FileRef
	Timestamp   time.Time
}

// FileRef is a file path reference extracted from an event payload.
// Content is not populated here — that is the Fetcher's job.
type FileRef struct {
	Path   string // repository-relative path
	Status string // "added", "modified", "removed"
}

// Provider ingests CommitEvents from a source. The interface intentionally
// does not assume that a global public event stream is available — providers
// vary widely in what they can expose.
type Provider interface {
	// Name returns a stable identifier for this provider (e.g. "github").
	Name() string

	// Stream emits CommitEvents until ctx is cancelled or an unrecoverable
	// error occurs. The error channel receives at most one value before close.
	// Both channels are always closed when Stream exits.
	Stream(ctx context.Context) (<-chan CommitEvent, <-chan error)
}
