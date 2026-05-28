package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/ingestion"
	"github.com/bugsyhewitt/seance/internal/scan"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

const awsRuleTOML = `
[[rules]]
id = "aws-access-key-id"
description = "AWS Access Key ID"
regex = '''AKIA[A-Z0-9]{16}'''
keywords = ["AKIA"]
`

const ghRuleTOML = `
[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
keywords = ["ghp_"]

[[rules]]
id = "github-oauth"
description = "GitHub OAuth Token"
regex = '''gho_[0-9a-zA-Z]{36}'''
keywords = ["gho_"]
`

const emptyTOML = `title = "no rules here"`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// TestReloadSignatures_SwapsRuleSet verifies that reloadSignatures replaces the
// engine's active rules when the file on disk changes.
func TestReloadSignatures_SwapsRuleSet(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sigs.toml", awsRuleTOML)

	rs, err := ruleset.LoadFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	engine := scan.New(rs.Rules)
	if engine.RuleCount() != 1 {
		t.Fatalf("initial rule count: got %d, want 1", engine.RuleCount())
	}

	// Rewrite the same path with a two-rule set, then reload.
	writeFile(t, dir, "sigs.toml", ghRuleTOML)
	reloadSignatures(engine, path)

	if engine.RuleCount() != 2 {
		t.Errorf("after reload, rule count: got %d, want 2", engine.RuleCount())
	}
}

// TestReloadSignatures_KeepsRulesOnParseError verifies that a malformed file
// leaves the previously active rules intact (a typo must not silence a monitor).
func TestReloadSignatures_KeepsRulesOnParseError(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sigs.toml", awsRuleTOML)

	rs, _ := ruleset.LoadFile(path)
	engine := scan.New(rs.Rules)

	// Corrupt the file with invalid TOML.
	writeFile(t, dir, "sigs.toml", "this is = = not valid toml [[[")
	reloadSignatures(engine, path)

	if engine.RuleCount() != 1 {
		t.Errorf("after failed reload, rule count: got %d, want 1 (rules must be preserved)", engine.RuleCount())
	}
}

// TestReloadSignatures_KeepsRulesOnMissingFile verifies that a vanished file is
// handled gracefully — active rules are preserved.
func TestReloadSignatures_KeepsRulesOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sigs.toml", awsRuleTOML)

	rs, _ := ruleset.LoadFile(path)
	engine := scan.New(rs.Rules)

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	reloadSignatures(engine, path)

	if engine.RuleCount() != 1 {
		t.Errorf("after reload of missing file, rule count: got %d, want 1", engine.RuleCount())
	}
}

// TestReloadSignatures_SkipsEmptyRuleSet verifies that a file parsing to zero
// rules is rejected so an accidental empty file cannot disable detection.
func TestReloadSignatures_SkipsEmptyRuleSet(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sigs.toml", awsRuleTOML)

	rs, _ := ruleset.LoadFile(path)
	engine := scan.New(rs.Rules)

	writeFile(t, dir, "sigs.toml", emptyTOML)
	reloadSignatures(engine, path)

	if engine.RuleCount() != 1 {
		t.Errorf("after reload of empty rule set, rule count: got %d, want 1 (must keep prior rules)", engine.RuleCount())
	}
}

// TestReloadSignatures_LoadsRealDefaultSet sanity-checks reloading against the
// shipped default ruleset so the test exercises the real file format.
func TestReloadSignatures_LoadsRealDefaultSet(t *testing.T) {
	// Locate the repo's default signatures from the cmd/seance test dir.
	path := filepath.Join("..", "..", "signatures", "default.toml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("default signatures not found at %s: %v", path, err)
	}
	engine := scan.New(nil)
	if engine.RuleCount() != 0 {
		t.Fatalf("expected empty engine, got %d rules", engine.RuleCount())
	}
	reloadSignatures(engine, path)
	if engine.RuleCount() == 0 {
		t.Error("reloading the default ruleset should load at least one rule")
	}
	// Smoke: the reloaded engine can scan without error.
	content := fetch.FileContent{
		Event:   ingestion.CommitEvent{RepoOwner: "alice", RepoName: "repo", CommitSHA: "abc"},
		FileRef: ingestion.FileRef{Path: ".env"},
		Patch:   "nothing interesting here",
		Lines:   []string{"nothing interesting here"},
	}
	if _, err := engine.Scan(context.Background(), content); err != nil {
		t.Fatalf("scan after default reload: %v", err)
	}
}
