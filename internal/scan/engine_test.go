package scan_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

func TestEngine_FindsAWSKey(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:          "aws-access-key-id",
			Description: "AWS Access Key ID",
			Regex:       `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			Keywords:    []string{"AKIA"},
		},
	}

	var findings []output.Finding
	sink := &captureSink{findings: &findings}
	engine := scan.New(rules, sink)

	content := fetch.FileContent{
		Event:   ingestion.CommitEvent{RepoOwner: "alice", RepoName: "repo", CommitSHA: "abc123"},
		FileRef: ingestion.FileRef{Path: ".env", Status: "added"},
		Patch:   "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
		Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	}

	n, err := engine.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 finding, got %d", n)
	}
	redacted := findings[0].Redacted
	if redacted == "" {
		t.Error("Redacted must not be empty")
	}
	// AKIAIOSFODNN7EXAMPLE is 20 chars (< minRevealLen=24), so expect fingerprint.
	if !strings.HasPrefix(redacted, "sha256:") && !containsStars(redacted) {
		t.Errorf("expected sha256 fingerprint or starred redaction, got %q", redacted)
	}
	// Must never contain raw secret material.
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("Redacted must not contain raw secret")
	}
}

func TestEngine_NoFindingsOnAllowList(t *testing.T) {
	rules := []ruleset.Rule{
		{
			ID:       "aws-access-key-id",
			Regex:    `(?:AKIA)[A-Z0-9]{16}`,
			Keywords: []string{"AKIA"},
			AllowList: ruleset.AllowList{
				StopWords: []string{"AKIAIOSFODNN7EXAMPLE"},
			},
		},
	}
	var findings []output.Finding
	engine := scan.New(rules, &captureSink{findings: &findings})
	content := fetch.FileContent{
		Patch: "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		Lines: []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	}
	n, _ := engine.Scan(context.Background(), content)
	if n != 0 {
		t.Errorf("expected 0 findings (allowlisted), got %d", n)
	}
}

type captureSink struct{ findings *[]output.Finding }

func (c *captureSink) Emit(_ context.Context, f output.Finding) error {
	*c.findings = append(*c.findings, f)
	return nil
}
func (c *captureSink) Close() error { return nil }

func containsStars(s string) bool {
	for _, c := range s {
		if c == '*' {
			return true
		}
	}
	return false
}
