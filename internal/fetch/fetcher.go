// Package fetch retrieves commit diff content for commits that survived
// the pre-filter stage. One HTTP request per commit returns the full patch
// for all changed files, keeping budget well within the 5,000 req/hr ceiling.
package fetch

import (
	"context"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

// FileContent holds the fetched diff content of a single changed file.
// Content is empty if the file was skipped (binary, oversized, or errored).
type FileContent struct {
	Event   ingestion.CommitEvent
	FileRef ingestion.FileRef
	Patch   string   // unified diff patch for this file
	Lines   []string // patch split into lines for scanning
	Skipped bool     // true if content was not fetched (binary, too large, error)
	SkipReason string
}

// Fetcher retrieves file content for a given commit and file reference.
type Fetcher interface {
	// Fetch retrieves the diff patch for a single file in a commit.
	// Returns a FileContent with Skipped=true if the file should not be scanned.
	Fetch(ctx context.Context, event ingestion.CommitEvent, ref ingestion.FileRef) (FileContent, error)
}
