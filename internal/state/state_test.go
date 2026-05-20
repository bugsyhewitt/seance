package state_test

import (
	"path/filepath"
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
