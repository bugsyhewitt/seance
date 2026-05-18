package prefilter_test

import (
	"testing"

	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/prefilter"
)

func TestFilter_SkipsBotCommit(t *testing.T) {
	e := ingestion.CommitEvent{
		AuthorName: "dependabot[bot]",
		Files:      []ingestion.FileRef{{Path: "config/settings.yaml", Status: "modified"}},
	}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("bot commit should be filtered out")
	}
}

func TestFilter_SkipsNoFiles(t *testing.T) {
	e := ingestion.CommitEvent{AuthorName: "alice"}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("empty commit should be filtered out")
	}
}

func TestFilter_KeepsEnvFile(t *testing.T) {
	e := ingestion.CommitEvent{
		AuthorName: "alice",
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
	e := ingestion.CommitEvent{AuthorName: "alice", Files: files}
	d := prefilter.Filter(e)
	if d.Keep {
		t.Error("large commit should be filtered out")
	}
}
