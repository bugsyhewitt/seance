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
