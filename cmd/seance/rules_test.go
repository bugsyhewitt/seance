package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTOML writes content to a temp file with the given name and returns its
// path.
func writeTOML(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

const cleanRuleset = `
title = "test"
[[rules]]
id       = "aws-access-key-id"
regex    = '''AKIA[A-Z0-9]{16}'''
keywords = ["AKIA"]
`

const errorRuleset = `
title = "test"
[[rules]]
id       = "broken"
regex    = '''AKIA[A-Z0-9{16}'''
keywords = ["AKIA"]
`

const warningRuleset = `
title = "test"
[[rules]]
id    = "no-keywords"
regex = '''AKIA[A-Z0-9]{16}'''
`

func TestValidate_CleanFileExitsZero(t *testing.T) {
	dir := t.TempDir()
	p := writeTOML(t, dir, "clean.toml", cleanRuleset)

	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{p})

	if code != validateExitOK {
		t.Errorf("clean ruleset should exit %d, got %d (out=%q)", validateExitOK, code, out.String())
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("expected OK in report, got %q", out.String())
	}
}

func TestValidate_ErrorFileExitsOne(t *testing.T) {
	dir := t.TempDir()
	p := writeTOML(t, dir, "broken.toml", errorRuleset)

	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{p})

	if code != validateExitErrors {
		t.Errorf("ruleset with errors should exit %d, got %d", validateExitErrors, code)
	}
	if !strings.Contains(out.String(), "ERROR") {
		t.Errorf("expected ERROR diagnostic, got %q", out.String())
	}
	if !strings.Contains(out.String(), "broken") {
		t.Errorf("expected offending rule id in report, got %q", out.String())
	}
}

func TestValidate_WarningOnlyExitsZero(t *testing.T) {
	dir := t.TempDir()
	p := writeTOML(t, dir, "warn.toml", warningRuleset)

	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{p})

	// Warnings alone must not fail the validation — they inform, they don't block.
	if code != validateExitOK {
		t.Errorf("warning-only ruleset should exit %d, got %d (out=%q)", validateExitOK, code, out.String())
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("expected WARNING diagnostic, got %q", out.String())
	}
}

func TestValidate_UnparseableFileExitsTwo(t *testing.T) {
	dir := t.TempDir()
	p := writeTOML(t, dir, "garbage.toml", "this is = = not valid toml [[[")

	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{p})

	if code != validateExitIO {
		t.Errorf("unparseable file should exit %d, got %d", validateExitIO, code)
	}
	if !strings.Contains(out.String(), "FAILED to parse") {
		t.Errorf("expected parse-failure diagnostic, got %q", out.String())
	}
}

func TestValidate_MissingFileExitsTwo(t *testing.T) {
	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{filepath.Join(t.TempDir(), "does-not-exist.toml")})

	if code != validateExitIO {
		t.Errorf("missing file should exit %d, got %d", validateExitIO, code)
	}
	if !strings.Contains(errw.String(), "cannot access") {
		t.Errorf("expected access error on stderr, got %q", errw.String())
	}
}

func TestValidate_DirectoryValidatesAllTOML(t *testing.T) {
	dir := t.TempDir()
	writeTOML(t, dir, "a.toml", cleanRuleset)
	writeTOML(t, dir, "b.toml", errorRuleset)
	// A non-toml file in the directory must be ignored.
	writeTOML(t, dir, "README.md", "not a ruleset")

	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{dir})

	// One of the two .toml files has errors → overall exit 1.
	if code != validateExitErrors {
		t.Errorf("directory with one bad ruleset should exit %d, got %d", validateExitErrors, code)
	}
	report := out.String()
	if !strings.Contains(report, "a.toml") || !strings.Contains(report, "b.toml") {
		t.Errorf("both .toml files should appear in report, got %q", report)
	}
	if strings.Contains(report, "README.md") {
		t.Errorf("non-toml files must not be validated, got %q", report)
	}
}

func TestValidate_DefaultSignaturesAreClean(t *testing.T) {
	// The shipped default ruleset must validate clean through the CLI path,
	// exactly as an operator running `seance rules validate signatures/default.toml`
	// would see.
	var out, errw bytes.Buffer
	code := validate(&out, &errw, []string{"../../signatures/default.toml"})

	if code != validateExitOK {
		t.Errorf("default ruleset must validate clean, got exit %d: %q", code, out.String())
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("expected OK for default ruleset, got %q", out.String())
	}
}

func TestExpandRulesetPaths_DedupsAndSorts(t *testing.T) {
	dir := t.TempDir()
	z := writeTOML(t, dir, "z.toml", cleanRuleset)
	a := writeTOML(t, dir, "a.toml", cleanRuleset)

	// Pass the same file twice plus the directory; expect dedup and sorted order.
	files, err := expandRulesetPaths([]string{z, z, dir})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// z appears explicitly and via the dir; a appears via the dir. Dedup → 2.
	if len(files) != 2 {
		t.Fatalf("expected 2 deduplicated files, got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "a.toml" || filepath.Base(files[1]) != "z.toml" {
		t.Errorf("files should be sorted, got %v", files)
	}
	_ = a
}
