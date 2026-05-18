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
}

func runScan(_ *cobra.Command, _ []string) error {
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
