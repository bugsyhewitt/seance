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

	"github.com/bugsyhewitt/seance/pkg/config"
)

var cfg = config.Defaults()

var rootCmd = &cobra.Command{
	Use:   "seance",
	Short: "séance — listening to what the dead repos whisper",
	Long: `séance watches the GitHub public commit stream and surfaces leaked
credentials (API keys, tokens, private keys, .env files).

Findings are redacted: séance shows you where to look and what to rotate,
not the full secret. It does not verify credentials — that is your call.`,
	RunE: runScan,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfg.GitHubToken, "token", cfg.GitHubToken, "GitHub personal access token")
	rootCmd.PersistentFlags().StringVar(&cfg.SignaturesPath, "signatures", cfg.SignaturesPath, "path to TOML signatures file")
	rootCmd.PersistentFlags().StringVar(&cfg.OutputFormat, "output", cfg.OutputFormat, "output format: json")
	rootCmd.PersistentFlags().StringVar(&cfg.StateDir, "state-dir", cfg.StateDir, "directory for persistent state")
	rootCmd.PersistentFlags().IntVar(&cfg.PollIntervalSec, "poll-interval", cfg.PollIntervalSec, "poll interval in seconds")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.Watch, "watch", cfg.Watch, "keyword to monitor via the GitHub commit Search API for targeted/org-scoped coverage, e.g. --watch acme-corp (repeatable); runs alongside the global events stream, empty disables it")
	rootCmd.PersistentFlags().BoolVar(&cfg.ForcePush, "force-push", cfg.ForcePush, "detect force-push history rewrites and scan the orphaned diff (one extra compare request per force-push)")
	rootCmd.PersistentFlags().StringVar(&cfg.SuppressFile, "suppress-file", cfg.SuppressFile, "path to a newline-delimited list of finding fingerprints to always ignore (the .gitleaksignore analogue); '#' comments allowed")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookURL, "webhook-url", cfg.WebhookURL, "POST each finding (redacted) as JSON to this URL; empty disables the webhook sink")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.WebhookHeaders, "webhook-header", cfg.WebhookHeaders, "header added to every webhook POST as KEY:VALUE (repeatable, e.g. Authorization:Bearer xyz)")
	rootCmd.PersistentFlags().Float64Var(&cfg.WebhookMinConfidence, "webhook-min-confidence", cfg.WebhookMinConfidence, "only POST findings with confidence at or above this threshold (0.0-1.0)")
	rootCmd.PersistentFlags().BoolVar(&cfg.TUI, "tui", cfg.TUI, "render a live, confidence-colored terminal feed of findings instead of raw NDJSON on stdout; falls back to NDJSON automatically when stdout is not a TTY")
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
