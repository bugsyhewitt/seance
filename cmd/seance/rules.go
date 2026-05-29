package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// rulesCmd groups ruleset-management subcommands. Today it carries only
// `validate`; future tooling (e.g. `rules list`, `rules test`) slots here.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Inspect and validate detection rulesets",
	Long: `Tools for working with séance's gitleaks-compatible TOML rulesets.

The scan engine is fail-safe by design: a rule with a malformed regex — or an
allowlist with a malformed pattern — is silently skipped at runtime so a bad
edit can never crash a run-for-days monitor. The cost is that a typo silently
disables detection with no signal. 'rules validate' is the pre-flight check that
surfaces those defects before you deploy.`,
}

// validateCmd implements `seance rules validate [path ...]`. With no path it
// validates the configured --signatures file; with one or more paths it
// validates each (a path may be a TOML file or a directory of .toml files).
var validateCmd = &cobra.Command{
	Use:   "validate [path ...]",
	Short: "Validate one or more ruleset files before deploying them",
	Long: `Validate parses each ruleset and reports the defects the scan engine
would silently tolerate at runtime: regexes that do not compile, allowlist
patterns that do not compile, missing or duplicate rule ids, out-of-range
secretGroup indices, and rules with no keywords or an impossible entropy floor.

With no path argument, the file named by --signatures is validated. Otherwise
each argument is validated; a directory argument validates every *.toml file
within it (non-recursively).

Exit status is 0 when no errors are found (warnings alone do not fail), 1 when
any error is found, and 2 when a file cannot be read or parsed.`,
	RunE: runValidate,
}

func init() {
	rulesCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(rulesCmd)
}

// validateExit is the process exit code distinguishing the three outcomes.
const (
	validateExitOK     = 0 // no errors (warnings allowed)
	validateExitErrors = 1 // validation errors found
	validateExitIO     = 2 // a file could not be read or parsed
)

func runValidate(cmd *cobra.Command, args []string) error {
	paths := args
	if len(paths) == 0 {
		paths = []string{cfg.SignaturesPath}
	}
	code := validate(cmd.OutOrStdout(), cmd.ErrOrStderr(), paths)
	os.Exit(code)
	return nil // unreachable; os.Exit above always fires
}

// validate runs the validation over the given paths, writing the report to out
// and any I/O diagnostics to errw, and returns the process exit code. It does
// not call os.Exit itself, so it is directly testable.
func validate(out, errw io.Writer, paths []string) int {
	files, err := expandRulesetPaths(paths)
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return validateExitIO
	}
	if len(files) == 0 {
		fmt.Fprintln(errw, "error: no ruleset files to validate")
		return validateExitIO
	}

	anyErrors := false
	anyIO := false
	for _, f := range files {
		rs, err := ruleset.LoadFile(f)
		if err != nil {
			fmt.Fprintf(out, "%s: FAILED to parse: %v\n", f, err)
			anyIO = true
			continue
		}
		problems := ruleset.Validate(rs)
		printFileReport(out, f, len(rs.Rules), problems)
		if ruleset.HasErrors(problems) {
			anyErrors = true
		}
	}

	switch {
	case anyIO:
		return validateExitIO
	case anyErrors:
		return validateExitErrors
	default:
		return validateExitOK
	}
}

// printFileReport writes a per-file validation report: a header line, every
// problem (errors then warnings, already sorted by Validate), and a summary.
func printFileReport(w io.Writer, path string, ruleCount int, problems []ruleset.Problem) {
	errs, warns := 0, 0
	for _, p := range problems {
		if p.Severity == ruleset.SeverityError {
			errs++
		} else {
			warns++
		}
	}

	if len(problems) == 0 {
		fmt.Fprintf(w, "%s: OK — %d rule(s), no problems\n", path, ruleCount)
		return
	}

	fmt.Fprintf(w, "%s: %d rule(s), %d error(s), %d warning(s)\n", path, ruleCount, errs, warns)
	for _, p := range problems {
		fmt.Fprintf(w, "  %s\n", p.String())
	}
}

// expandRulesetPaths resolves the caller's path arguments into a concrete,
// deduplicated, sorted list of ruleset files. A file path is taken as-is; a
// directory contributes its *.toml entries (non-recursive). A path that does
// not exist is an error.
func expandRulesetPaths(paths []string) ([]string, error) {
	seen := make(map[string]struct{})
	var files []string
	add := func(p string) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		files = append(files, p)
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("cannot access %q: %w", p, err)
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("cannot read directory %q: %w", p, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if filepath.Ext(e.Name()) != ".toml" {
				continue
			}
			add(filepath.Join(p, e.Name()))
		}
	}

	sort.Strings(files)
	return files, nil
}
