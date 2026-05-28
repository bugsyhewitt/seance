// Package ingestion defines the core types and Provider interface for ingesting
// public commit events. Implementations are not required to expose a global
// event stream — some providers may only support targeted repository scanning.
package ingestion

import (
	"context"
	"time"
)

// CommitEvent represents a single commit observed from a provider.
// When FilesKnown is true, Files contains the set of changed paths extracted
// from the event payload. When false, the payload did not include file paths
// (e.g. GitHub's new events API format) and the fetcher must discover them.
type CommitEvent struct {
	Provider    string
	RepoOwner   string
	RepoName    string
	CommitSHA   string
	CommitMsg   string
	AuthorName  string
	AuthorEmail string
	Files       []FileRef
	FilesKnown  bool // true when Files was populated from the event payload
	Timestamp   time.Time

	// ForcePush is true when this event was emitted because the push reset HEAD
	// backward (a force-push that rewrites history). These are the highest-signal
	// events for intentional secret removal: a developer commits a key, notices,
	// and force-pushes history back to before the mistake. The leaked secret lives
	// in the commit(s) that became dangling between BeforeSHA and CommitSHA.
	ForcePush bool

	// BeforeSHA is the SHA HEAD pointed at before this push. For a force-push it
	// identifies the (now-dangling) tip whose diff would otherwise be orphaned.
	// The fetcher compares BeforeSHA...CommitSHA to recover the buried content.
	BeforeSHA string
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
