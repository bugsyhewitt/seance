package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/ingestion/fake"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/output/ndjson"
	"github.com/bugsyhewitt/seance/internal/prefilter"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// TestEndToEnd_FindsSecretInFakeEvent exercises the full pipeline through the
// NDJSON sink, covering: fake provider → prefilter → fetch → scan → redact → emit.
func TestEndToEnd_FindsSecretInFakeEvent(t *testing.T) {
	event := ingestion.CommitEvent{
		Provider: "fake", RepoOwner: "alice", RepoName: "repo",
		CommitSHA: "deadbeef", AuthorName: "alice",
		Files:      []ingestion.FileRef{{Path: ".env", Status: "added"}},
		FilesKnown: true,
	}

	provider := fake.New(event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, _ := provider.Stream(ctx)

	rules := []ruleset.Rule{{
		ID: "aws-test", Regex: `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}

	// Wire the real NDJSON sink — this is the end of the pipeline.
	var buf bytes.Buffer
	sink := ndjson.New(&buf)
	engine := scan.New(rules, sink)

	for e := range events {
		d := prefilter.Filter(e)
		if !d.Keep {
			continue
		}
		for _, ref := range d.Files {
			fc := fetch.FileContent{
				Event:   e,
				FileRef: ref,
				Patch:   "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
				Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
			}
			engine.Scan(ctx, fc)
		}
	}
	sink.Close()

	// Parse NDJSON output and verify structure.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 NDJSON line, got %d: %q", len(lines), buf.String())
	}

	var finding output.Finding
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("parse NDJSON: %v", err)
	}

	if finding.RuleID != "aws-test" {
		t.Errorf("rule_id: got %q, want %q", finding.RuleID, "aws-test")
	}
	if finding.RepoOwner != "alice" {
		t.Errorf("repo_owner: got %q", finding.RepoOwner)
	}
	if finding.FilePath != ".env" {
		t.Errorf("file_path: got %q", finding.FilePath)
	}
	if finding.Redacted == "" {
		t.Error("redacted field must not be empty")
	}
	// Raw secret must not appear in the emitted JSON.
	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("NDJSON output must not contain raw secret value")
	}
	// 20-char secret (< 24) → fingerprint; must start with sha256:
	if !strings.HasPrefix(finding.Redacted, "sha256:") {
		t.Errorf("expected sha256 fingerprint for short secret, got %q", finding.Redacted)
	}
}
