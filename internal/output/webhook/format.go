package webhook

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bugsyhewitt/seance/internal/output"
)

// Format selects how a Finding is rendered into the POST body.
//
// The webhook sink began life as a generic JSON relay: it POSTed the raw
// (already-redacted) Finding object, which a custom endpoint or a SIEM can
// consume directly. But the two channels operators most want to page —
// Slack and Discord incoming webhooks — do not accept an arbitrary JSON object;
// each expects a specific message-text envelope (`{"text": ...}` for Slack,
// `{"content": ...}` for Discord). Pointing --webhook-url straight at a Slack or
// Discord webhook with the default JSON body produces a silent 400 and no alert.
//
// Format lets séance render the redacted Finding into the envelope the target
// platform expects, so an operator can wire --webhook-url directly to a Slack or
// Discord incoming webhook with no relay in between. Every format renders only
// already-redacted/locator fields of the Finding — the never-emit-raw-secrets
// invariant holds for all of them, exactly as it does for the raw-JSON body.
type Format string

const (
	// FormatJSON POSTs the redacted Finding object as JSON (the original,
	// default behavior). Suited to custom endpoints and SIEM ingestion.
	FormatJSON Format = "json"
	// FormatSlack POSTs a Slack-compatible `{"text": "..."}` envelope carrying a
	// human-readable, redacted summary of the finding. Point --webhook-url at a
	// Slack incoming webhook.
	FormatSlack Format = "slack"
	// FormatDiscord POSTs a Discord-compatible `{"content": "..."}` envelope
	// carrying the same redacted summary. Point --webhook-url at a Discord
	// channel webhook.
	FormatDiscord Format = "discord"
)

// ParseFormat validates and normalizes a webhook format string. An empty string
// maps to FormatJSON (the default). Unknown values are rejected so a typo fails
// loudly at startup rather than silently producing bodies the endpoint rejects.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(FormatJSON):
		return FormatJSON, nil
	case string(FormatSlack):
		return FormatSlack, nil
	case string(FormatDiscord):
		return FormatDiscord, nil
	default:
		return "", fmt.Errorf("unknown webhook format %q (want one of: json, slack, discord)", s)
	}
}

// renderBody serializes a Finding into the request body for the given format.
// It only ever reads redacted/locator fields of the Finding, so no format can
// emit raw secret material.
func renderBody(format Format, f output.Finding) ([]byte, error) {
	switch format {
	case FormatSlack:
		return json.Marshal(map[string]string{"text": findingMessage(f)})
	case FormatDiscord:
		return json.Marshal(map[string]string{"content": findingMessage(f)})
	default: // FormatJSON
		return json.Marshal(f)
	}
}

// findingMessage builds the human-readable, redacted one-message summary used by
// the Slack and Discord envelopes. It composes only redacted/locator fields —
// rule, repo, file/line, the redacted value, confidence, and fingerprint — never
// any raw secret material.
func findingMessage(f output.Finding) string {
	desc := f.RuleDesc
	if desc == "" {
		desc = f.RuleID
	}

	var b strings.Builder
	fmt.Fprintf(&b, "séance leak alert: %s", desc)
	if f.RuleDesc != "" && f.RuleID != "" {
		fmt.Fprintf(&b, " (%s)", f.RuleID)
	}
	b.WriteByte('\n')

	repo := f.RepoOwner
	if f.RepoName != "" {
		if repo != "" {
			repo += "/"
		}
		repo += f.RepoName
	}
	if repo != "" {
		fmt.Fprintf(&b, "repo: %s", repo)
		if f.Provider != "" {
			fmt.Fprintf(&b, " (%s)", f.Provider)
		}
		b.WriteByte('\n')
	}

	if f.FilePath != "" {
		fmt.Fprintf(&b, "file: %s", f.FilePath)
		if f.LineNumber > 0 {
			fmt.Fprintf(&b, ":%d", f.LineNumber)
		}
		b.WriteByte('\n')
	}

	if f.CommitSHA != "" {
		fmt.Fprintf(&b, "commit: %s\n", f.CommitSHA)
	}

	fmt.Fprintf(&b, "redacted: %s\n", f.Redacted)
	fmt.Fprintf(&b, "confidence: %.2f", f.Confidence)
	if f.Fingerprint != "" {
		fmt.Fprintf(&b, "\nfingerprint: %s", f.Fingerprint)
	}

	return b.String()
}
