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
	"github.com/bugsyhewitt/seance/internal/output/sarif"
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
				Patch:   "+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R\n",
				Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R"},
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
	if strings.Contains(buf.String(), "AKIA2E4F6H8J0L2N4P6R") {
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
			Patch:   "+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R\n",
			Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R"},
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
	if strings.Contains(string(fileData), "AKIA2E4F6H8J0L2N4P6R") {
		t.Error("file sink output must not contain raw secret value")
	}
	// The file record and the stdout record describe the same finding.
	if !strings.Contains(stdoutBuf.String(), "aws-test") {
		t.Errorf("stdout sink should also have received the finding: %q", stdoutBuf.String())
	}
}

// TestEndToEnd_SarifSinkTeesAlongsideStdout exercises the --sarif-file
// composition: the same Finding fans out through the real scan engine to BOTH the
// stdout NDJSON sink and the SARIF sink (as the pipeline wires them when
// --sarif-file is set). It asserts the SARIF document captures the identical
// redacted finding as a valid result, and never the raw secret.
func TestEndToEnd_SarifSinkTeesAlongsideStdout(t *testing.T) {
	event := ingestion.CommitEvent{
		Provider: "fake", RepoOwner: "alice", RepoName: "repo",
		CommitSHA: "deadbeef", AuthorName: "alice",
		Files:      []ingestion.FileRef{{Path: ".env", Status: "added"}},
		FilesKnown: true,
	}

	ctx := context.Background()

	rules := []ruleset.Rule{{
		ID: "aws-test", Description: "AWS test key", Regex: `AKIA[A-Z0-9]{16}`,
		Keywords: []string{"AKIA"},
	}}

	var stdoutBuf bytes.Buffer
	path := filepath.Join(t.TempDir(), "scan.sarif")
	sarifSink := sarif.New(path, "0.2.0-test")
	engine := scan.New(rules, ndjson.New(&stdoutBuf), sarifSink)

	d := prefilter.Filter(event)
	for _, ref := range d.Files {
		fc := fetch.FileContent{
			Event:   event,
			FileRef: ref,
			Patch:   "+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R\n",
			Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIA2E4F6H8J0L2N4P6R"},
		}
		if _, err := engine.Scan(ctx, fc); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	// SARIF is written once on Close (mirrors the pipeline's deferred Close).
	if err := sarifSink.Close(); err != nil {
		t.Fatalf("sarif sink close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sarif: %v\n%s", err, string(data))
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("sarif version: got %v want 2.1.0", doc["version"])
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 sarif result, got %d: %s", len(results), string(data))
	}
	res := results[0].(map[string]any)
	if res["ruleId"] != "aws-test" {
		t.Errorf("sarif ruleId: got %v want aws-test", res["ruleId"])
	}
	loc := res["locations"].([]any)[0].(map[string]any)
	uri := loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
	if !strings.Contains(uri, "alice/repo") || !strings.Contains(uri, ".env") {
		t.Errorf("sarif artifact uri missing repo/path: %q", uri)
	}
	if strings.Contains(string(data), "AKIA2E4F6H8J0L2N4P6R") {
		t.Error("SARIF output must not contain raw secret value")
	}
	// The SARIF report and the stdout record describe the same finding.
	if !strings.Contains(stdoutBuf.String(), "aws-test") {
		t.Errorf("stdout sink should also have received the finding: %q", stdoutBuf.String())
	}
}

// TestEndToEnd_MinConfidenceGatesAllSinks proves the engine-wide --min-confidence
// floor (installed via WithMinConfidence, exactly as runPipeline does) suppresses
// a sub-threshold finding before it reaches ANY sink — here both the stdout NDJSON
// sink and a durable file sink — while a high-confidence finding in the same scan
// passes to both. This is the cross-sink noise gate: one dial, every channel.
func TestEndToEnd_MinConfidenceGatesAllSinks(t *testing.T) {
	ctx := context.Background()

	// Two rules: a high-specificity AWS rule (0.80 base + 0.10 prefix bonus = 0.90)
	// and a generic rule that, on a non-suspicious path, scores 0.80 − 0.10 = 0.70.
	rules := []ruleset.Rule{
		{ID: "aws-high", Regex: `AKIA[A-Z0-9]{16}`, Keywords: []string{"AKIA"}},
		{ID: "generic-low", Regex: `secret-token-[A-Za-z0-9]{20}`, Keywords: []string{"secret-token"}, Tags: []string{"generic"}},
	}

	var stdoutBuf bytes.Buffer
	filePath := filepath.Join(t.TempDir(), "findings.ndjson")
	fileSink, err := outfile.New(filePath)
	if err != nil {
		t.Fatalf("file sink: %v", err)
	}
	// Floor of 0.80 — admits the 0.90 AWS finding, drops the 0.70 generic one.
	engine := scan.New(rules, ndjson.New(&stdoutBuf), fileSink).WithMinConfidence(0.80)

	// Non-suspicious path so the generic rule keeps its 0.70 (a .env path would
	// cancel the penalty and let it through, defeating the test).
	fc := fetch.FileContent{
		Event:   ingestion.CommitEvent{Provider: "fake", RepoOwner: "alice", RepoName: "repo", CommitSHA: "deadbeef"},
		FileRef: ingestion.FileRef{Path: "docs/README.md", Status: "added"},
		Patch:   "+AKIA2E4F6H8J0L2N4P6R secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn\n",
		Lines:   []string{"+AKIA2E4F6H8J0L2N4P6R secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn"},
	}
	n, err := engine.Scan(ctx, fc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 finding above the floor, got %d", n)
	}
	if got := engine.BelowConfidenceCount(); got != 1 {
		t.Fatalf("expected 1 sub-floor drop, got %d", got)
	}
	if err := fileSink.Close(); err != nil {
		t.Fatalf("file sink close: %v", err)
	}

	// The high-confidence rule passed to stdout; the low-confidence one did not.
	if !strings.Contains(stdoutBuf.String(), "aws-high") {
		t.Errorf("stdout missing the above-floor finding: %q", stdoutBuf.String())
	}
	if strings.Contains(stdoutBuf.String(), "generic-low") {
		t.Errorf("stdout must NOT contain the sub-floor finding: %q", stdoutBuf.String())
	}

	// Same gating reached the durable file sink — the floor is engine-wide, not
	// per-sink, so every channel sees the identical filtered set.
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read file sink: %v", err)
	}
	if !strings.Contains(string(data), "aws-high") {
		t.Errorf("file sink missing the above-floor finding: %q", string(data))
	}
	if strings.Contains(string(data), "generic-low") {
		t.Errorf("file sink must NOT contain the sub-floor finding: %q", string(data))
	}
	// Never-store-raw invariant holds on both the passed and the dropped path.
	if strings.Contains(string(data), "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn") || strings.Contains(stdoutBuf.String(), "secret-token-Ab3Cd4Ef5Gh6Ij7Kl8Mn") {
		t.Error("raw secret value leaked into a sink")
	}
}
