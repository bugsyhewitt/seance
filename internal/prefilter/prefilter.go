// Package prefilter discards commits that are unlikely to contain secrets,
// using ONLY data already present in the event payload — no extra API calls.
// This is the primary mechanism that keeps séance within the 5,000 req/hr budget.
//
// Filter heuristics (payload-only, zero requests):
//   - Skip commits with no added/modified files
//   - Skip commits from known automation accounts (suffix "[bot]")
//   - Skip commits with more than maxFilesThreshold changed files
//   - Keep commits where at least one file matches a suspicious path pattern
package prefilter

import (
	"path/filepath"
	"strings"

	"github.com/bugsyhewitt/seance/internal/ingestion"
)

const maxFilesThreshold = 50

// Decision carries the outcome of filtering a single commit event.
type Decision struct {
	Keep   bool
	Files  []ingestion.FileRef // filtered subset worth fetching
	Reason string              // human-readable reason for Keep=false (observability)
}

// suspiciousExtensions are file extensions that frequently contain secrets.
var suspiciousExtensions = map[string]bool{
	".pem": true, ".key": true, ".pfx": true, ".p12": true, ".jks": true,
	".cer": true, ".crt": true, ".ovpn": true, ".kdbx": true, ".asc": true,
	".env": true, ".htpasswd": true, ".netrc": true, ".npmrc": true,
}

// suspiciousSegments are path segments or filenames that frequently contain secrets.
var suspiciousSegments = []string{
	"secret", "credential", "password", "passwd", "private", "token",
	"apikey", "api_key", "access_key", "auth_key", "signing_key",
	".aws", ".ssh", ".gnupg", "vault", "id_rsa", "id_ed25519",
	"config.json", "settings.json", ".travis.yml", "circle.yml",
}

// Filter applies payload-only heuristics to a CommitEvent and returns a Decision.
//
// When event.FilesKnown is false (GitHub's new API format no longer includes
// file paths in the event payload), only non-file heuristics are applied and
// the commit is passed through for the fetcher to discover its changed files.
func Filter(event ingestion.CommitEvent) Decision {
	// Always apply bot check — actor name is available regardless of format.
	if strings.HasSuffix(event.AuthorName, "[bot]") ||
		strings.HasSuffix(event.AuthorEmail, "[bot]") {
		return Decision{Keep: false, Reason: "bot commit"}
	}

	// Force-push events are the highest-signal indicator of intentional secret
	// removal, so they always pass through even though file paths are unknown
	// (FilesKnown=false). The pipeline recovers the orphaned diff via the
	// compare API and applies post-fetch path filtering.
	if event.ForcePush {
		return Decision{Keep: true, Files: nil, Reason: "force-push"}
	}

	if !event.FilesKnown {
		// File paths are unknown; pass through so the fetcher can discover them.
		// Post-fetch filtering is applied by the pipeline using IsInteresting.
		return Decision{Keep: true, Files: nil}
	}

	if len(event.Files) == 0 {
		return Decision{Keep: false, Reason: "no files"}
	}
	if len(event.Files) > maxFilesThreshold {
		return Decision{Keep: false, Reason: "too many files (likely generated)"}
	}

	var interesting []ingestion.FileRef
	for _, f := range event.Files {
		if f.Status == "removed" {
			continue
		}
		if IsInteresting(f.Path) {
			interesting = append(interesting, f)
		}
	}

	if len(interesting) == 0 {
		return Decision{Keep: false, Reason: "no interesting files"}
	}
	return Decision{Keep: true, Files: interesting}
}

// IsInteresting reports whether a file path is worth scanning for secrets.
// Exported so the pipeline can apply post-fetch filtering when file paths
// are not known from the event payload.
func IsInteresting(path string) bool {
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(path))
	if suspiciousExtensions[ext] {
		return true
	}
	for _, seg := range suspiciousSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}
