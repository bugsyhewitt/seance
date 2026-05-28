// Package state manages séance's polling and deduplication state across restarts.
// State is small and must be persisted to disk so that:
//   - Polls resume from the correct ETag (avoids re-processing seen events)
//   - Seen commits are not re-scanned after a restart
//   - Cold starts can either resume from cursor or start fresh (configurable)
package state

import "time"

// State is the full persisted state for séance. Serialised to disk as JSON.
type State struct {
	// ETag is the last GitHub API ETag value for conditional GET requests.
	// An empty ETag means no prior poll has completed.
	ETag string `json:"etag,omitempty"`

	// PollCursor is a provider-specific opaque value marking the last processed
	// position in the event stream (e.g. event ID for GitHub).
	PollCursor string `json:"poll_cursor,omitempty"`

	// SeenCommits maps commit SHA to first-seen time. Used for deduplication.
	// Entries older than SeenTTL are evicted to bound memory/disk usage.
	SeenCommits map[string]time.Time `json:"seen_commits"`

	// SeenFindings maps a stable, privacy-preserving finding fingerprint to its
	// first-seen time. It suppresses cross-run re-leaks: the same secret
	// re-committed across forks, re-pushed after a restart, or matched by two
	// overlapping rules is alerted once, not every time it reappears. The
	// fingerprint is derived only from redacted/locator material (never raw
	// secret bytes), so persisting this map cannot leak a credential. Entries
	// are evicted on the same TTL as SeenCommits to bound state size.
	SeenFindings map[string]time.Time `json:"seen_findings"`

	// LastUpdated is set each time State is persisted.
	LastUpdated time.Time `json:"last_updated"`
}

// Storage loads and persists séance State.
type Storage interface {
	// Load returns the persisted State, or a fresh State if none exists.
	Load() (*State, error)
	// Save persists the State atomically (write-then-rename).
	Save(s *State) error
}

// New returns an empty State ready for a fresh run.
func New() *State {
	return &State{
		SeenCommits:  make(map[string]time.Time),
		SeenFindings: make(map[string]time.Time),
		LastUpdated:  time.Now(),
	}
}

// Seen reports whether commitSHA has been processed before.
func (s *State) Seen(commitSHA string) bool {
	_, ok := s.SeenCommits[commitSHA]
	return ok
}

// Mark records commitSHA as processed.
func (s *State) Mark(commitSHA string) {
	s.SeenCommits[commitSHA] = time.Now()
}

// SeenFinding reports whether a finding with this fingerprint has been emitted
// before (within the eviction window). A nil/uninitialised map reads as unseen.
func (s *State) SeenFinding(fingerprint string) bool {
	_, ok := s.SeenFindings[fingerprint]
	return ok
}

// MarkFinding records a finding fingerprint as emitted. It lazily initialises
// the map so State values loaded from older state files (which lack the field)
// remain usable.
func (s *State) MarkFinding(fingerprint string) {
	if s.SeenFindings == nil {
		s.SeenFindings = make(map[string]time.Time)
	}
	s.SeenFindings[fingerprint] = time.Now()
}

// Evict removes seen-commit and seen-finding entries older than ttl to bound
// state size. Both dedup maps share the same retention window so the persisted
// state file stays bounded across long-running deployments.
func (s *State) Evict(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	for sha, t := range s.SeenCommits {
		if t.Before(cutoff) {
			delete(s.SeenCommits, sha)
		}
	}
	for fp, t := range s.SeenFindings {
		if t.Before(cutoff) {
			delete(s.SeenFindings, fp)
		}
	}
}
