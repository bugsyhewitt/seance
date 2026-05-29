// séance — listening to what the dead repos whisper.
// Public-commit secret scanner. Watches the GitHub public event stream and
// surfaces leaked credentials as fast as the source API allows.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/bugsyhewitt/seance/pkg/config"
)

var cfg = config.Defaults()

// configPath is the optional path to a TOML config file (--config). When set,
// the file is loaded as the base configuration and any flag the operator passes
// explicitly overrides the corresponding file value (precedence: defaults <
// file < flags/env).
var configPath string

var rootCmd = &cobra.Command{
	Use:   "seance",
	Short: "séance — listening to what the dead repos whisper",
	Long: `séance watches the GitHub public commit stream and surfaces leaked
credentials (API keys, tokens, private keys, .env files).

Findings are redacted: séance shows you where to look and what to rotate,
not the full secret. It does not verify credentials — that is your call.

Configuration precedence (lowest to highest): built-in defaults, then a TOML
file passed with --config, then explicitly-set flags and environment variables.
A flag you pass always wins over the same field in the config file, so you can
keep a stable file and override one value on the command line.`,
	PersistentPreRunE: applyConfigFile,
	RunE:              runScan,
}

// applyConfigFile implements the defaults < file < flags precedence. cobra has
// already parsed the command line into cfg by the time PersistentPreRunE runs,
// so cfg holds (defaults overlaid with explicitly-set flags). We load the file
// as a fresh base, then re-apply only the flags the operator actually changed on
// top of it — leaving file values in place for every flag left at its default.
func applyConfigFile(cmd *cobra.Command, _ []string) error {
	if configPath == "" {
		return nil // no file: cfg already holds defaults+flags, nothing to merge
	}

	// Snapshot the post-parse cfg so we can recover explicitly-set flag values
	// after we overwrite cfg with the file layer.
	parsed := cfg

	fileCfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	changed := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) { changed[f.Name] = true })

	cfg = mergeConfig(fileCfg, parsed, changed)
	return nil
}

// mergeConfig applies séance's defaults < file < flags precedence. fileCfg is
// the configuration loaded from --config (already overlaid on defaults); parsed
// is the cfg cobra produced from defaults+flags; changed names the flags the
// operator set explicitly. The result is fileCfg with every explicitly-set
// flag's value copied over from parsed, so a flag always beats the file while
// file values survive for flags left at their default.
//
// It is a pure function of its inputs (no globals, no I/O) so the precedence
// rules can be tested directly.
func mergeConfig(fileCfg, parsed config.Config, changed map[string]bool) config.Config {
	out := fileCfg
	for name := range changed {
		switch name {
		case "token":
			out.GitHubToken = parsed.GitHubToken
		case "signatures":
			out.SignaturesPath = parsed.SignaturesPath
		case "enable-rule":
			out.EnableRules = parsed.EnableRules
		case "disable-rule":
			out.DisableRules = parsed.DisableRules
		case "output":
			out.OutputFormat = parsed.OutputFormat
		case "output-file":
			out.OutputPath = parsed.OutputPath
		case "output-max-bytes":
			out.OutputMaxBytes = parsed.OutputMaxBytes
		case "sarif-file":
			out.SarifPath = parsed.SarifPath
		case "state-dir":
			out.StateDir = parsed.StateDir
		case "poll-interval":
			out.PollIntervalSec = parsed.PollIntervalSec
		case "watch":
			out.Watch = parsed.Watch
		case "watch-since":
			out.WatchSince = parsed.WatchSince
		case "watch-until":
			out.WatchUntil = parsed.WatchUntil
		case "watch-interval":
			out.WatchIntervalSec = parsed.WatchIntervalSec
		case "force-push":
			out.ForcePush = parsed.ForcePush
		case "suppress-file":
			out.SuppressFile = parsed.SuppressFile
		case "min-confidence":
			out.MinConfidence = parsed.MinConfidence
		case "webhook-url":
			out.WebhookURL = parsed.WebhookURL
		case "webhook-header":
			out.WebhookHeaders = parsed.WebhookHeaders
		case "webhook-min-confidence":
			out.WebhookMinConfidence = parsed.WebhookMinConfidence
		case "webhook-format":
			out.WebhookFormat = parsed.WebhookFormat
		case "tui":
			out.TUI = parsed.TUI
		case "webhook-listen":
			out.WebhookListenAddr = parsed.WebhookListenAddr
		case "webhook-listen-secret":
			out.WebhookListenSecret = parsed.WebhookListenSecret
		}
	}
	return out
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to a TOML config file holding any of the flags below; built-in defaults are the base, the file overlays them, and any flag you also pass on the command line overrides the file (defaults < file < flags); empty means flags-only")
	rootCmd.PersistentFlags().StringVar(&cfg.GitHubToken, "token", cfg.GitHubToken, "GitHub personal access token")
	rootCmd.PersistentFlags().StringVar(&cfg.SignaturesPath, "signatures", cfg.SignaturesPath, "path to TOML signatures file")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.EnableRules, "enable-rule", cfg.EnableRules, "rule ID to enable — when set (repeatable), ONLY the listed rules run and every other loaded rule is dropped (allowlist); empty runs all rules; the gitleaks --enable-rule analogue, applied on top of --signatures without editing it")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.DisableRules, "disable-rule", cfg.DisableRules, "rule ID to disable (repeatable) — the listed rules are dropped from the loaded ruleset; applied after --enable-rule and always wins over it; silence a noisy rule without editing --signatures")
	rootCmd.PersistentFlags().StringVar(&cfg.OutputFormat, "output", cfg.OutputFormat, "stdout streaming format: 'json' (newline-delimited JSON, the default) or 'text' (one compact human-readable line per finding, grep-friendly); for a SARIF report use --sarif-file; ignored when --tui takes over an interactive stdout")
	rootCmd.PersistentFlags().StringVar(&cfg.OutputPath, "output-file", cfg.OutputPath, "also append redacted NDJSON findings to this file (created with its parent dir; append mode); '-' or empty means stdout only — pairs with --tui to keep a machine-readable record while watching the live feed")
	rootCmd.PersistentFlags().Int64Var(&cfg.OutputMaxBytes, "output-max-bytes", cfg.OutputMaxBytes, "rotate the --output-file when it would exceed this many bytes: the active file is renamed to <file>.1 (older generations shift up, a few are kept) and a fresh file is opened, bounding total disk for a run-forever monitor; 0 (default) appends forever; ignored unless --output-file names a real file")
	rootCmd.PersistentFlags().StringVar(&cfg.SarifPath, "sarif-file", cfg.SarifPath, "also write a SARIF 2.1.0 report of all findings to this file (ingestible by GitHub code scanning and other SARIF tools); written once on shutdown; empty disables it")
	rootCmd.PersistentFlags().StringVar(&cfg.StateDir, "state-dir", cfg.StateDir, "directory for persistent state")
	rootCmd.PersistentFlags().IntVar(&cfg.PollIntervalSec, "poll-interval", cfg.PollIntervalSec, "poll interval in seconds")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.Watch, "watch", cfg.Watch, "keyword to monitor via the GitHub commit Search API for targeted/org-scoped coverage, e.g. --watch acme-corp (repeatable); runs alongside the global events stream, empty disables it")
	rootCmd.PersistentFlags().StringVar(&cfg.WatchSince, "watch-since", cfg.WatchSince, "scope --watch search results to commits with a committer-date on or after this date (YYYY-MM-DD); applies only to the search provider; empty leaves the search corpus unscoped")
	rootCmd.PersistentFlags().StringVar(&cfg.WatchUntil, "watch-until", cfg.WatchUntil, "scope --watch search results to commits with a committer-date on or before this date (YYYY-MM-DD); applies only to the search provider; empty leaves the search corpus unscoped")
	rootCmd.PersistentFlags().IntVar(&cfg.WatchIntervalSec, "watch-interval", cfg.WatchIntervalSec, "poll cadence in seconds for the --watch Search-API provider (the targeted/org-scoped axis); applies only to --watch, not the global events stream (--poll-interval); 0 keeps the conservative 90s default; values below 10s are clamped up to protect the 30 req/min Search-API quota")
	rootCmd.PersistentFlags().BoolVar(&cfg.ForcePush, "force-push", cfg.ForcePush, "detect force-push history rewrites and scan the orphaned diff (one extra compare request per force-push)")
	rootCmd.PersistentFlags().StringVar(&cfg.SuppressFile, "suppress-file", cfg.SuppressFile, "path to a newline-delimited list of finding fingerprints to always ignore (the .gitleaksignore analogue); '#' comments allowed")
	rootCmd.PersistentFlags().Float64Var(&cfg.MinConfidence, "min-confidence", cfg.MinConfidence, "global confidence floor (0.0-1.0): drop findings below this score before they reach ANY sink (stdout, --output-file, --sarif-file, --tui, webhook); 0 emits everything; raise it to surface only high-confidence findings")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookURL, "webhook-url", cfg.WebhookURL, "POST each finding (redacted) as JSON to this URL; empty disables the webhook sink")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.WebhookHeaders, "webhook-header", cfg.WebhookHeaders, "header added to every webhook POST as KEY:VALUE (repeatable, e.g. Authorization:Bearer xyz)")
	rootCmd.PersistentFlags().Float64Var(&cfg.WebhookMinConfidence, "webhook-min-confidence", cfg.WebhookMinConfidence, "only POST findings with confidence at or above this threshold (0.0-1.0)")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookFormat, "webhook-format", cfg.WebhookFormat, "webhook POST body shape: 'json' (redacted Finding object, default), 'slack' ({\"text\":...} envelope), or 'discord' ({\"content\":...} envelope); slack/discord let --webhook-url point straight at an incoming webhook with no relay")
	rootCmd.PersistentFlags().BoolVar(&cfg.TUI, "tui", cfg.TUI, "render a live, confidence-colored terminal feed of findings instead of raw NDJSON on stdout; falls back to NDJSON automatically when stdout is not a TTY")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookListenAddr, "webhook-listen", cfg.WebhookListenAddr, "TCP address on which séance listens for inbound GitHub push webhooks (e.g. ':8099' or '127.0.0.1:8099'); when set, every push delivery is scanned immediately with no polling or rate-limit cost — additive alongside the global events stream and --watch; empty disables the receiver")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookListenSecret, "webhook-listen-secret", cfg.WebhookListenSecret, "HMAC-SHA256 secret configured on the GitHub webhook 'Secret' field; when set, every delivery's X-Hub-Signature-256 is verified before the body is parsed; running without a secret is allowed but séance logs a warning")
}

func runScan(_ *cobra.Command, _ []string) error {
	// --token takes precedence; GITHUB_TOKEN env var is the Docker-friendly fallback.
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "séance %s — listening to what the dead repos whisper\n", cfg.Version)

	return runPipeline(ctx, cfg)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
