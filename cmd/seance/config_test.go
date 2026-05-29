package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/seance/pkg/config"
)

// TestMergeConfig_FlagsBeatFile verifies the defaults < file < flags precedence:
// a flag the operator changed wins over the file, while file values survive for
// flags left at their default.
func TestMergeConfig_FlagsBeatFile(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.PollIntervalSec = 30
	fileCfg.WebhookURL = "https://file.example.com"
	fileCfg.MinConfidence = 0.4

	parsed := config.Defaults()
	parsed.PollIntervalSec = 90                    // operator passed --poll-interval 90
	parsed.WebhookURL = "https://flag.example.com" // operator did NOT pass --webhook-url
	parsed.MinConfidence = 0.9                     // operator passed --min-confidence 0.9

	// Only poll-interval and min-confidence were explicitly set on the CLI.
	changed := map[string]bool{"poll-interval": true, "min-confidence": true}

	got := mergeConfig(fileCfg, parsed, changed)

	if got.PollIntervalSec != 90 {
		t.Errorf("PollIntervalSec = %d, want 90 (flag overrides file)", got.PollIntervalSec)
	}
	if got.MinConfidence != 0.9 {
		t.Errorf("MinConfidence = %v, want 0.9 (flag overrides file)", got.MinConfidence)
	}
	// webhook-url was not changed on the CLI, so the file value must survive even
	// though parsed carried a different (default-bound) value.
	if got.WebhookURL != "https://file.example.com" {
		t.Errorf("WebhookURL = %q, want the file value (no flag set)", got.WebhookURL)
	}
}

// TestMergeConfig_BoolFlagOverride covers the tricky case where the flag value
// equals a zero/default value: an explicitly-set --force-push=false must beat a
// file that says force_push = true.
func TestMergeConfig_BoolFlagOverride(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.ForcePush = true

	parsed := config.Defaults()
	parsed.ForcePush = false // --force-push=false

	got := mergeConfig(fileCfg, parsed, map[string]bool{"force-push": true})

	if got.ForcePush != false {
		t.Errorf("ForcePush = %v, want false (explicit flag beats file)", got.ForcePush)
	}
}

// TestMergeConfig_NoFlagsKeepsFile verifies that with no flags changed the file
// configuration is returned untouched.
func TestMergeConfig_NoFlagsKeepsFile(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.StateDir = "/var/lib/seance"
	fileCfg.TUI = true

	got := mergeConfig(fileCfg, config.Defaults(), map[string]bool{})

	if !reflect.DeepEqual(got, fileCfg) {
		t.Errorf("merged = %+v, want untouched file %+v", got, fileCfg)
	}
}

// TestMergeConfig_RuleSelectionFlagsBeatFile verifies the enable/disable rule
// flags follow the same defaults < file < flags precedence: an explicitly-set
// --disable-rule wins over the file, while a file's enable_rules survives when
// --enable-rule is not passed on the CLI.
func TestMergeConfig_RuleSelectionFlagsBeatFile(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.EnableRules = []string{"aws-access-key-id"}
	fileCfg.DisableRules = []string{"generic-api-key"}

	parsed := config.Defaults()
	parsed.EnableRules = []string{"should-not-win"}     // operator did NOT pass --enable-rule
	parsed.DisableRules = []string{"stripe-secret-key"} // operator passed --disable-rule

	// Only disable-rule was set on the CLI.
	got := mergeConfig(fileCfg, parsed, map[string]bool{"disable-rule": true})

	if !reflect.DeepEqual(got.DisableRules, []string{"stripe-secret-key"}) {
		t.Errorf("DisableRules = %v, want the flag value (flag overrides file)", got.DisableRules)
	}
	if !reflect.DeepEqual(got.EnableRules, []string{"aws-access-key-id"}) {
		t.Errorf("EnableRules = %v, want the file value (no flag set)", got.EnableRules)
	}
}

// TestMergeConfig_TagFilterFlagsBeatFile verifies the categorical tag-filter
// flags follow the defaults < file < flags precedence: a CLI --exclude-tag wins
// over the file, while a file's include_tags survives when --tag is not passed.
func TestMergeConfig_TagFilterFlagsBeatFile(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.IncludeTags = []string{"aws"}
	fileCfg.ExcludeTags = []string{"generic"}

	parsed := config.Defaults()
	parsed.IncludeTags = []string{"should-not-win"} // operator did NOT pass --tag
	parsed.ExcludeTags = []string{"test-fixture"}   // operator passed --exclude-tag

	// Only exclude-tag was set on the CLI.
	got := mergeConfig(fileCfg, parsed, map[string]bool{"exclude-tag": true})

	if !reflect.DeepEqual(got.ExcludeTags, []string{"test-fixture"}) {
		t.Errorf("ExcludeTags = %v, want the flag value (flag overrides file)", got.ExcludeTags)
	}
	if !reflect.DeepEqual(got.IncludeTags, []string{"aws"}) {
		t.Errorf("IncludeTags = %v, want the file value (no flag set)", got.IncludeTags)
	}
}

// TestMergeConfig_OutputMaxBytesFlagBeatsFile verifies --output-max-bytes follows
// the defaults < file < flags precedence and that the file value survives when the
// flag is not set on the CLI.
func TestMergeConfig_OutputMaxBytesFlagBeatsFile(t *testing.T) {
	fileCfg := config.Defaults()
	fileCfg.OutputMaxBytes = 1 << 20 // 1 MiB from the file

	parsed := config.Defaults()
	parsed.OutputMaxBytes = 5 << 20 // operator passed --output-max-bytes 5MiB

	// Flag set: it wins.
	got := mergeConfig(fileCfg, parsed, map[string]bool{"output-max-bytes": true})
	if got.OutputMaxBytes != 5<<20 {
		t.Errorf("OutputMaxBytes = %d, want 5MiB (flag overrides file)", got.OutputMaxBytes)
	}

	// Flag not set: the file value survives.
	got = mergeConfig(fileCfg, parsed, map[string]bool{})
	if got.OutputMaxBytes != 1<<20 {
		t.Errorf("OutputMaxBytes = %d, want 1MiB (file value survives)", got.OutputMaxBytes)
	}
}

// TestApplyConfigFile_EndToEnd drives the real cobra command with a --config
// file and an overriding flag, exercising the full PersistentPreRunE path and
// the package globals it mutates.
func TestApplyConfigFile_EndToEnd(t *testing.T) {
	// Restore the package globals after the test so we don't leak state.
	origCfg, origPath := cfg, configPath
	t.Cleanup(func() { cfg, configPath = origCfg, origPath })

	path := filepath.Join(t.TempDir(), "seance.toml")
	content := `
poll_interval_sec = 45
webhook_url = "https://file.example.com/hook"
min_confidence = 0.3
state_dir = "/srv/seance-state"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Reset cfg to defaults, then parse a command line that sets --config and
	// overrides poll-interval on the CLI. RunE is replaced with a no-op so we
	// don't start the pipeline.
	cfg = config.Defaults()
	rootCmd.RunE = func(_ *cobra.Command, _ []string) error { return nil }
	rootCmd.SetArgs([]string{"--config", path, "--poll-interval", "120"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Flag override wins.
	if cfg.PollIntervalSec != 120 {
		t.Errorf("PollIntervalSec = %d, want 120 (flag overrides file)", cfg.PollIntervalSec)
	}
	// File values survive for flags not set on the CLI.
	if cfg.WebhookURL != "https://file.example.com/hook" {
		t.Errorf("WebhookURL = %q, want the file value", cfg.WebhookURL)
	}
	if cfg.MinConfidence != 0.3 {
		t.Errorf("MinConfidence = %v, want 0.3 from file", cfg.MinConfidence)
	}
	if cfg.StateDir != "/srv/seance-state" {
		t.Errorf("StateDir = %q, want the file value", cfg.StateDir)
	}
}

// TestApplyConfigFile_MissingFileErrors verifies a bad --config path fails the
// command rather than silently running on defaults.
func TestApplyConfigFile_MissingFileErrors(t *testing.T) {
	origCfg, origPath := cfg, configPath
	t.Cleanup(func() { cfg, configPath = origCfg, origPath })

	cfg = config.Defaults()
	rootCmd.RunE = func(_ *cobra.Command, _ []string) error { return nil }
	rootCmd.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "nope.toml")})

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected Execute to fail on a missing --config file, got nil")
	}
}
