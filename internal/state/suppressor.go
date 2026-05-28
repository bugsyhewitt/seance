package state

import "sync"

// FindingSuppressor adapts a *State plus an operator suppress-list into the
// cross-run deduplication interface the scan engine consumes (scan.Suppressor).
//
// It serves two suppression sources:
//
//   - Persistent seen-set: fingerprints recorded in State.SeenFindings during
//     this or any prior run (loaded from disk on startup, evicted on the shared
//     TTL). This is what suppresses a re-leak — the same secret re-pushed,
//     forked, or matched by two overlapping rules alerts once, not every time.
//   - Operator suppress-list: an immutable set of fingerprints the operator has
//     explicitly chosen to always ignore (the .gitleaksignore analogue, loaded
//     from a --suppress-file). These are never alerted and never recorded as
//     "seen", so removing one from the file re-enables alerting immediately.
//
// All access to the underlying State is serialised through mu, which the caller
// shares with every other reader/writer of the State (the pipeline's stMu), so
// finding-suppression bookkeeping cannot race the seen-commit map, eviction, or
// the final persist.
type FindingSuppressor struct {
	mu       *sync.Mutex
	st       *State
	suppress map[string]struct{} // operator always-ignore list; read-only after construction
}

// NewFindingSuppressor builds a suppressor over st, guarded by mu (the same
// mutex the caller uses for all other State access), with an optional operator
// suppress-list. A nil or empty suppressList means "suppress only known
// re-leaks". mu must not be nil.
func NewFindingSuppressor(mu *sync.Mutex, st *State, suppressList []string) *FindingSuppressor {
	set := make(map[string]struct{}, len(suppressList))
	for _, fp := range suppressList {
		if fp != "" {
			set[fp] = struct{}{}
		}
	}
	return &FindingSuppressor{mu: mu, st: st, suppress: set}
}

// Suppress reports whether a finding with this fingerprint should be dropped:
// true if it is on the operator suppress-list or has already been seen in this
// or a prior run.
func (f *FindingSuppressor) Suppress(fingerprint string) bool {
	if _, listed := f.suppress[fingerprint]; listed {
		return true
	}
	f.mu.Lock()
	seen := f.st.SeenFinding(fingerprint)
	f.mu.Unlock()
	return seen
}

// MarkSeen records a fingerprint in the persistent seen-set so a later identical
// finding suppresses. The engine calls this only for findings it actually
// emitted (i.e. not already suppressed).
func (f *FindingSuppressor) MarkSeen(fingerprint string) {
	f.mu.Lock()
	f.st.MarkFinding(fingerprint)
	f.mu.Unlock()
}
