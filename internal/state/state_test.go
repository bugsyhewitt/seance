package state_test

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bugsyhewitt/seance/internal/state"
)

func TestJSONFileStorage_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := state.NewJSONFileStorage(filepath.Join(dir, "state.json"))

	s, err := store.Load()
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if s.SeenCommits == nil {
		t.Fatal("Load empty: SeenCommits is nil")
	}

	s.ETag = "\"abc123\""
	s.PollCursor = "evt_42"
	s.Mark("deadbeef")
	if err := store.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := store.Load()
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if s2.ETag != "\"abc123\"" {
		t.Errorf("ETag: got %q want %q", s2.ETag, "\"abc123\"")
	}
	if !s2.Seen("deadbeef") {
		t.Error("Seen: deadbeef not found after reload")
	}
}

// TestRestartDeduplication proves that commits marked during "run 1" are
// still deduplicated after save → load ("run 2"), so no duplicate findings
// occur across a restart.
func TestRestartDeduplication(t *testing.T) {
	dir := t.TempDir()
	store := state.NewJSONFileStorage(filepath.Join(dir, "state.json"))

	// Run 1: process some commits and persist state.
	run1 := state.New()
	run1SHAs := []string{"sha-aaa", "sha-bbb", "sha-ccc"}
	for _, sha := range run1SHAs {
		run1.Mark(sha)
	}
	if err := store.Save(run1); err != nil {
		t.Fatalf("save run1 state: %v", err)
	}

	// Run 2: load state as if restarting.
	run2, err := store.Load()
	if err != nil {
		t.Fatalf("load run2 state: %v", err)
	}

	// All commits from run 1 must be seen in run 2 — no re-processing.
	for _, sha := range run1SHAs {
		if !run2.Seen(sha) {
			t.Errorf("restart: commit %q should be seen after reload", sha)
		}
	}

	// A new commit not seen in run 1 must NOT be considered seen.
	if run2.Seen("sha-new") {
		t.Error("restart: unseen commit should not be seen after reload")
	}
}

func TestState_Evict(t *testing.T) {
	s := state.New()
	s.SeenCommits["old"] = time.Now().Add(-48 * time.Hour)
	s.SeenCommits["new"] = time.Now()
	s.Evict(24 * time.Hour)
	if s.Seen("old") {
		t.Error("old commit should have been evicted")
	}
	if !s.Seen("new") {
		t.Error("new commit should not have been evicted")
	}
}

// TestState_Evict_SevenDayTTL exercises the exact TTL the pipeline threads
// through from config.SeenTTLDays (default 7), asserting that entries older
// than the window are gone while recent ones survive, and that the tracked
// count is bounded after eviction.
func TestState_Evict_SevenDayTTL(t *testing.T) {
	const ttl = 7 * 24 * time.Hour
	s := state.New()

	// Three entries clearly past the 7-day window.
	s.SeenCommits["stale-1"] = time.Now().Add(-8 * 24 * time.Hour)
	s.SeenCommits["stale-2"] = time.Now().Add(-10 * 24 * time.Hour)
	s.SeenCommits["stale-3"] = time.Now().Add(-30 * 24 * time.Hour)
	// Two entries comfortably inside the window.
	s.SeenCommits["fresh-1"] = time.Now().Add(-1 * time.Hour)
	s.SeenCommits["fresh-2"] = time.Now().Add(-6 * 24 * time.Hour)

	s.Evict(ttl)

	for _, sha := range []string{"stale-1", "stale-2", "stale-3"} {
		if s.Seen(sha) {
			t.Errorf("entry %q older than TTL should have been evicted", sha)
		}
	}
	for _, sha := range []string{"fresh-1", "fresh-2"} {
		if !s.Seen(sha) {
			t.Errorf("entry %q within TTL should have survived eviction", sha)
		}
	}
	if got := len(s.SeenCommits); got != 2 {
		t.Errorf("seen_commits_tracked after eviction: got %d, want 2", got)
	}
}

// TestState_Evict_Persisted proves the bound holds across a save/load cycle:
// after eviction and persistence, stale entries do not return on reload.
func TestState_Evict_Persisted(t *testing.T) {
	dir := t.TempDir()
	store := state.NewJSONFileStorage(filepath.Join(dir, "state.json"))

	s := state.New()
	s.SeenCommits["stale"] = time.Now().Add(-9 * 24 * time.Hour)
	s.SeenCommits["fresh"] = time.Now()

	s.Evict(7 * 24 * time.Hour)
	if err := store.Save(s); err != nil {
		t.Fatalf("save after evict: %v", err)
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("load after evict: %v", err)
	}
	if reloaded.Seen("stale") {
		t.Error("evicted entry must not reappear after reload")
	}
	if !reloaded.Seen("fresh") {
		t.Error("surviving entry must persist across reload")
	}
}

// ── Cross-run finding deduplication (POST_V01 Item 4) ───────────────────────────

// TestState_SeenFinding_MarkAndCheck covers the basic seen-set semantics for
// finding fingerprints, including lazy map initialisation on a zero-value State
// (as produced by unmarshalling an older state file that predates the field).
func TestState_SeenFinding_MarkAndCheck(t *testing.T) {
	var s state.State // zero value: SeenFindings is nil
	if s.SeenFinding("sha256:abcd") {
		t.Error("nil seen-findings map must read as unseen")
	}
	s.MarkFinding("sha256:abcd")
	if !s.SeenFinding("sha256:abcd") {
		t.Error("fingerprint should be seen after MarkFinding")
	}
	if s.SeenFinding("sha256:ef01") {
		t.Error("a different fingerprint must remain unseen")
	}
}

// TestState_New_InitialisesSeenFindings ensures New() returns a ready-to-use
// finding seen-set so callers never hit a nil map on a fresh run.
func TestState_New_InitialisesSeenFindings(t *testing.T) {
	s := state.New()
	if s.SeenFindings == nil {
		t.Fatal("New(): SeenFindings must be initialised")
	}
}

// TestState_Evict_TrimsSeenFindings proves the shared eviction window bounds the
// finding seen-set the same way it bounds SeenCommits: stale fingerprints are
// dropped, fresh ones survive.
func TestState_Evict_TrimsSeenFindings(t *testing.T) {
	s := state.New()
	s.SeenFindings["stale"] = time.Now().Add(-9 * 24 * time.Hour)
	s.SeenFindings["fresh"] = time.Now()

	s.Evict(7 * 24 * time.Hour)

	if s.SeenFinding("stale") {
		t.Error("finding fingerprint older than TTL should be evicted")
	}
	if !s.SeenFinding("fresh") {
		t.Error("finding fingerprint within TTL should survive eviction")
	}
}

// TestState_SeenFindings_PersistAcrossRestart is the cross-run guarantee: a
// fingerprint recorded in run 1 is still suppressed in run 2 after a save/load
// cycle — the re-leak suppression the feature exists to provide.
func TestState_SeenFindings_PersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	store := state.NewJSONFileStorage(filepath.Join(dir, "state.json"))

	run1 := state.New()
	run1.MarkFinding("sha256:deadbeef")
	if err := store.Save(run1); err != nil {
		t.Fatalf("save run1: %v", err)
	}

	run2, err := store.Load()
	if err != nil {
		t.Fatalf("load run2: %v", err)
	}
	if !run2.SeenFinding("sha256:deadbeef") {
		t.Error("finding fingerprint from run 1 must be suppressed in run 2")
	}
	if run2.SeenFinding("sha256:cafef00d") {
		t.Error("unseen fingerprint must not be suppressed after reload")
	}
}

// ── FindingSuppressor ───────────────────────────────────────────────────────────

// TestFindingSuppressor_ReLeakSuppressed verifies the core dedup loop: the first
// time a fingerprint is seen it passes (Suppress=false), and after MarkSeen the
// same fingerprint suppresses.
func TestFindingSuppressor_ReLeakSuppressed(t *testing.T) {
	var mu sync.Mutex
	s := state.New()
	sup := state.NewFindingSuppressor(&mu, s, nil)

	const fp = "sha256:11111111"
	if sup.Suppress(fp) {
		t.Fatal("first sighting must not be suppressed")
	}
	sup.MarkSeen(fp)
	if !sup.Suppress(fp) {
		t.Error("a re-detected finding must be suppressed after MarkSeen")
	}
	if sup.Suppress("sha256:22222222") {
		t.Error("a distinct finding must not be suppressed")
	}
}

// TestFindingSuppressor_SuppressListHonored verifies that an operator
// suppress-list entry is always suppressed and is never recorded as "seen", so
// removing it from the list re-enables alerting.
func TestFindingSuppressor_SuppressListHonored(t *testing.T) {
	var mu sync.Mutex
	s := state.New()
	const listed = "sha256:abcdef01"
	sup := state.NewFindingSuppressor(&mu, s, []string{listed, "", "  ignored-empty-handled "})

	if !sup.Suppress(listed) {
		t.Error("suppress-list fingerprint must be suppressed")
	}
	// Listed entries are never marked seen — the seen-set stays empty for them,
	// so deleting the list entry re-enables alerting.
	if s.SeenFinding(listed) {
		t.Error("suppress-list entry must not be recorded in the seen-set")
	}
	if sup.Suppress("sha256:not-listed") {
		t.Error("a fingerprint absent from list and seen-set must pass")
	}
}

// TestFindingSuppressor_SharesStateMutex exercises the suppressor concurrently to
// confirm (under -race) that all State access is serialised through the shared
// mutex with no data race.
func TestFindingSuppressor_SharesStateMutex(t *testing.T) {
	var mu sync.Mutex
	s := state.New()
	sup := state.NewFindingSuppressor(&mu, s, nil)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fp := "sha256:" + string(rune('a'+id%8))
			for j := 0; j < 500; j++ {
				if !sup.Suppress(fp) {
					sup.MarkSeen(fp)
				}
			}
		}(i)
	}
	wg.Wait()
}
