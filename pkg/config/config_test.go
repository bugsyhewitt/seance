package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeTemp writes content to a temp file inside t.TempDir and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func TestLoad_OverlaysDefaults(t *testing.T) {
	// Only a few keys are set; everything else must retain Defaults().
	path := writeTemp(t, "seance.toml", `
poll_interval_sec = 30
min_confidence = 0.7
webhook_url = "https://hooks.example.com/x"
watch = ["acme-corp", "internal.example.com"]
watch_interval_sec = 45
force_push = false
`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	def := Defaults()

	// Overridden values come from the file.
	if got.PollIntervalSec != 30 {
		t.Errorf("PollIntervalSec = %d, want 30", got.PollIntervalSec)
	}
	if got.MinConfidence != 0.7 {
		t.Errorf("MinConfidence = %v, want 0.7", got.MinConfidence)
	}
	if got.WebhookURL != "https://hooks.example.com/x" {
		t.Errorf("WebhookURL = %q, want the file value", got.WebhookURL)
	}
	if len(got.Watch) != 2 || got.Watch[0] != "acme-corp" || got.Watch[1] != "internal.example.com" {
		t.Errorf("Watch = %v, want [acme-corp internal.example.com]", got.Watch)
	}
	if got.WatchIntervalSec != 45 {
		t.Errorf("WatchIntervalSec = %d, want 45 (file override)", got.WatchIntervalSec)
	}
	// ForcePush defaults to true; the file sets it false — a bool override must
	// take effect even when the file value equals the zero value.
	if got.ForcePush != false {
		t.Errorf("ForcePush = %v, want false (file override)", got.ForcePush)
	}

	// Untouched values must equal the built-in defaults.
	if got.MaxFilesPerCommit != def.MaxFilesPerCommit {
		t.Errorf("MaxFilesPerCommit = %d, want default %d", got.MaxFilesPerCommit, def.MaxFilesPerCommit)
	}
	if got.SignaturesPath != def.SignaturesPath {
		t.Errorf("SignaturesPath = %q, want default %q", got.SignaturesPath, def.SignaturesPath)
	}
	if got.StateDir != def.StateDir {
		t.Errorf("StateDir = %q, want default %q", got.StateDir, def.StateDir)
	}
	if got.SeenTTLDays != def.SeenTTLDays {
		t.Errorf("SeenTTLDays = %d, want default %d", got.SeenTTLDays, def.SeenTTLDays)
	}
	if got.OutputPath != def.OutputPath {
		t.Errorf("OutputPath = %q, want default %q", got.OutputPath, def.OutputPath)
	}
	// Version is the build constant, never operator-set.
	if got.Version != def.Version {
		t.Errorf("Version = %q, want build default %q", got.Version, def.Version)
	}
}

func TestLoad_EmptyFileEqualsDefaults(t *testing.T) {
	path := writeTemp(t, "empty.toml", "# just a comment\n")

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !reflect.DeepEqual(got, Defaults()) {
		t.Errorf("empty config = %+v, want Defaults() %+v", got, Defaults())
	}
}

func TestLoad_MissingFileIsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("expected an error for a missing config file, got nil")
	}
	if !strings.Contains(err.Error(), "reading config file") {
		t.Errorf("error = %q, want it to mention reading the config file", err)
	}
}

func TestLoad_InvalidTOMLIsError(t *testing.T) {
	path := writeTemp(t, "bad.toml", "this is = = not valid toml [[[")

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected a parse error for invalid TOML, got nil")
	}
	if !strings.Contains(err.Error(), "parsing config file") {
		t.Errorf("error = %q, want it to mention parsing the config file", err)
	}
}

func TestLoad_UnknownKeyIsError(t *testing.T) {
	// A misspelled key must fail loudly rather than silently no-op — an operator
	// who types "webhook_ur" should be told, not have alerting silently off.
	path := writeTemp(t, "typo.toml", `webhook_ur = "https://oops.example.com"`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for an unknown config key, got nil")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("error = %q, want it to mention an unknown key", err)
	}
	if !strings.Contains(err.Error(), "webhook_ur") {
		t.Errorf("error = %q, want it to name the offending key", err)
	}
}

func TestLoad_StringSliceAndHeaders(t *testing.T) {
	path := writeTemp(t, "headers.toml", `
webhook_headers = ["Authorization:Bearer xyz", "X-Env:prod"]
webhook_format = "slack"
`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(got.WebhookHeaders) != 2 {
		t.Fatalf("WebhookHeaders len = %d, want 2", len(got.WebhookHeaders))
	}
	if got.WebhookHeaders[0] != "Authorization:Bearer xyz" {
		t.Errorf("WebhookHeaders[0] = %q", got.WebhookHeaders[0])
	}
	if got.WebhookFormat != "slack" {
		t.Errorf("WebhookFormat = %q, want slack", got.WebhookFormat)
	}
}

// TestLoad_OutputLimit verifies the output_limit TOML key decodes onto the
// OutputLimit field — the config-file half of the --output-limit flag, used by
// run-forever monitors that prefer a stable file to a long command line.
func TestLoad_OutputLimit(t *testing.T) {
	path := writeTemp(t, "limit.toml", `output_limit = 250`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.OutputLimit != 250 {
		t.Errorf("OutputLimit = %d, want 250 (from file)", got.OutputLimit)
	}

	// An omitted key must keep the default (0 — no cap).
	defPath := writeTemp(t, "default.toml", `# no output_limit set`)
	defGot, err := Load(defPath)
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if defGot.OutputLimit != 0 {
		t.Errorf("OutputLimit (omitted) = %d, want 0", defGot.OutputLimit)
	}
}

// TestLoad_DedupeWindow verifies the dedupe_window_days TOML key decodes onto
// the DedupeWindowDays field — the config-file half of the --dedupe-window
// flag for run-forever monitors that prefer a stable file to a long command
// line.
func TestLoad_DedupeWindow(t *testing.T) {
	path := writeTemp(t, "dw.toml", `dedupe_window_days = 30`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.DedupeWindowDays != 30 {
		t.Errorf("DedupeWindowDays = %d, want 30 (from file)", got.DedupeWindowDays)
	}

	// An omitted key must keep the default (0 — inherit SeenTTLDays).
	defPath := writeTemp(t, "default-dw.toml", `# no dedupe_window_days set`)
	defGot, err := Load(defPath)
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if defGot.DedupeWindowDays != 0 {
		t.Errorf("DedupeWindowDays (omitted) = %d, want 0 (inherits seen_ttl_days)", defGot.DedupeWindowDays)
	}
}

// TestLoad_RateLimit verifies the rate_limit TOML key decodes onto the
// RateLimit field — the config-file half of the --rate-limit flag, used by
// run-forever monitors that prefer a stable file to a long command line.
func TestLoad_RateLimit(t *testing.T) {
	path := writeTemp(t, "rl.toml", `rate_limit = 5.5`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.RateLimit != 5.5 {
		t.Errorf("RateLimit = %v, want 5.5 (from file)", got.RateLimit)
	}

	// An omitted key must keep the default (0 — no cap).
	defPath := writeTemp(t, "default-rl.toml", `# no rate_limit set`)
	defGot, err := Load(defPath)
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if defGot.RateLimit != 0 {
		t.Errorf("RateLimit (omitted) = %v, want 0", defGot.RateLimit)
	}
}

// TestLoad_CSVPath verifies the csv_path TOML key decodes onto the CSVPath
// field — the config-file half of the --csv-file flag, used by run-forever
// monitors that prefer a stable file to a long command line.
func TestLoad_CSVPath(t *testing.T) {
	path := writeTemp(t, "csv.toml", `csv_path = "/var/log/seance/findings.csv"`)

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got.CSVPath != "/var/log/seance/findings.csv" {
		t.Errorf("CSVPath = %q, want the file value", got.CSVPath)
	}

	// An omitted key must keep the default (empty — CSV sink disabled).
	defPath := writeTemp(t, "default-csv.toml", `# no csv_path set`)
	defGot, err := Load(defPath)
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if defGot.CSVPath != "" {
		t.Errorf("CSVPath (omitted) = %q, want empty (sink disabled)", defGot.CSVPath)
	}
}
