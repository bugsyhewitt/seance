package prefilter_test

import (
	"testing"

	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/prefilter"
)

func TestFilter_SkipsBotCommit(t *testing.T) {
	e := ingestion.CommitEvent{
		AuthorName: "dependabot[bot]",
		FilesKnown: true,
		Files:      []ingestion.FileRef{{Path: "config/settings.yaml", Status: "modified"}},
	}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("bot commit should be filtered out")
	}
}

func TestFilter_SkipsBotCommit_UnknownFiles(t *testing.T) {
	// Bot commits are dropped even when file paths are not known from the payload.
	e := ingestion.CommitEvent{AuthorName: "dependabot[bot]", FilesKnown: false}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("bot commit with unknown files should be filtered out")
	}
}

func TestFilter_SkipsNoFiles(t *testing.T) {
	// Known-empty file list (e.g. merge commit with no file changes).
	e := ingestion.CommitEvent{AuthorName: "alice", FilesKnown: true}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("commit with known-empty file list should be filtered out")
	}
}

func TestFilter_PassesThroughUnknownFiles(t *testing.T) {
	// New GitHub API format: no file info in payload → pass through for fetcher.
	e := ingestion.CommitEvent{AuthorName: "alice", FilesKnown: false}
	d := prefilter.Filter(e)
	if !d.Keep {
		t.Errorf("unknown-files commit should pass through, reason: %s", d.Reason)
	}
	if d.Files != nil {
		t.Error("pass-through decision should have nil Files (fetcher discovers them)")
	}
}

func TestFilter_KeepsEnvFile(t *testing.T) {
	e := ingestion.CommitEvent{
		AuthorName: "alice",
		FilesKnown: true,
		Files:      []ingestion.FileRef{{Path: ".env", Status: "added"}},
	}
	d := prefilter.Filter(e)
	if !d.Keep {
		t.Errorf("reason: %s", d.Reason)
	}
	if len(d.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(d.Files))
	}
}

func TestFilter_KeepsPemFile(t *testing.T) {
	e := ingestion.CommitEvent{
		AuthorName: "alice",
		FilesKnown: true,
		Files:      []ingestion.FileRef{{Path: "certs/server.pem", Status: "added"}},
	}
	d := prefilter.Filter(e)
	if !d.Keep {
		t.Errorf("reason: %s", d.Reason)
	}
}

func TestFilter_SkipsLargeCommit(t *testing.T) {
	var files []ingestion.FileRef
	for i := 0; i < 60; i++ {
		files = append(files, ingestion.FileRef{Path: "src/generated/file.go", Status: "added"})
	}
	e := ingestion.CommitEvent{AuthorName: "alice", FilesKnown: true, Files: files}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("large commit should be filtered out")
	}
}
