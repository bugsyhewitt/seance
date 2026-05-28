package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/ingestion/fake"
	"github.com/bugsyhewitt/seance/internal/output"
	outfile "github.com/bugsyhewitt/seance/internal/output/file"
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

// TestEndToEnd_FileSinkTeesAlongsideStdout exercises the --output-file
// composition: the same Finding fans out through the scan engine to BOTH the
// stdout NDJSON sink and the durable file sink (as the pipeline wires them when
// --output-file is set, including alongside --tui). It asserts the file captures
// the identical redacted record and never the raw secret.
func TestEndToEnd_FileSinkTeesAlongsideStdout(t *testing.T) {
	event := ingestion.CommitEvent{
		Provider: "fake", RepoOwner: "alice", RepoName: "repo",
		CommitSHA: "deadbeef", AuthorName: "alice",
		Files:      []ingestion.FileRef{{Path: ".env", Status: "added"}},
		FilesKnown: true,
	}

	ctx := context.Background()

	rules := []ruleset.Rule{{
		ID: "aws-test", Regex: `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}

	// Stdout sink + durable file sink, exactly as runPipeline composes them.
	var stdoutBuf bytes.Buffer
	path := filepath.Join(t.TempDir(), "findings.ndjson")
	fileSink, err := outfile.New(path)
	if err != nil {
		t.Fatalf("file sink: %v", err)
	}
	engine := scan.New(rules, ndjson.New(&stdoutBuf), fileSink)

	d := prefilter.Filter(event)
	for _, ref := range d.Files {
		fc := fetch.FileContent{
			Event:   event,
			FileRef: ref,
			Patch:   "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
			Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
		}
		if _, err := engine.Scan(ctx, fc); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	if err := fileSink.Close(); err != nil {
		t.Fatalf("file sink close: %v", err)
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file sink output: %v", err)
	}
	fileLines := strings.Split(strings.TrimSpace(string(fileData)), "\n")
	if len(fileLines) != 1 {
		t.Fatalf("expected 1 finding in file, got %d: %q", len(fileLines), string(fileData))
	}

	var ff output.Finding
	if err := json.Unmarshal([]byte(fileLines[0]), &ff); err != nil {
		t.Fatalf("parse file NDJSON: %v", err)
	}
	if ff.RuleID != "aws-test" || ff.FilePath != ".env" {
		t.Errorf("file finding mismatch: %+v", ff)
	}
	if ff.Redacted == "" {
		t.Error("file finding redacted field must not be empty")
	}
	if strings.Contains(string(fileData), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("file sink output must not contain raw secret value")
	}
	// The file record and the stdout record describe the same finding.
	if !strings.Contains(stdoutBuf.String(), "aws-test") {
		t.Errorf("stdout sink should also have received the finding: %q", stdoutBuf.String())
	}
}
