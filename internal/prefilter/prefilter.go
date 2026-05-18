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
	Keep  bool
	Files []ingestion.FileRef // filtered subset worth fetching
	Reason string             // human-readable reason for Keep=false (observability)
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
func Filter(event ingestion.CommitEvent) Decision {
	if len(event.Files) == 0 {
		return Decision{Keep: false, Reason: "no files"}
	}
	if len(event.Files) > maxFilesThreshold {
		return Decision{Keep: false, Reason: "too many files (likely generated)"}
	}
	if strings.HasSuffix(event.AuthorName, "[bot]") ||
		strings.HasSuffix(event.AuthorEmail, "[bot]") {
		return Decision{Keep: false, Reason: "bot commit"}
	}

	var interesting []ingestion.FileRef
	for _, f := range event.Files {
		if f.Status == "removed" {
			continue
		}
		if isInteresting(f.Path) {
			interesting = append(interesting, f)
		}
	}

	if len(interesting) == 0 {
		return Decision{Keep: false, Reason: "no interesting files"}
	}
	return Decision{Keep: true, Files: interesting}
}

func isInteresting(path string) bool {
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
