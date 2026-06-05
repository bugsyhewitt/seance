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
// consume directly. But the chat channels operators most want to page —
// Slack, Discord, and Microsoft Teams — do not accept an arbitrary JSON object;
// each expects a specific message envelope (`{"text": ...}` for Slack,
// `{"content": ...}` for Discord, a `MessageCard` document for Teams). Pointing
// --webhook-url straight at one of those webhooks with the default JSON body
// produces a silent rejection and no alert.
//
// Format lets séance render the redacted Finding into the envelope the target
// platform expects, so an operator can wire --webhook-url directly to a Slack,
// Discord, or Teams incoming webhook with no relay in between. Every format
// renders only already-redacted/locator fields of the Finding — the
// never-emit-raw-secrets invariant holds for all of them, exactly as it does for
// the raw-JSON body.
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
	// FormatTeams POSTs a Microsoft Teams-compatible legacy MessageCard document
	// (`@type: MessageCard`) carrying the same redacted summary. Teams incoming
	// webhooks reject a bare `{"text": ...}` body — they require the connector
	// card envelope — so this is the format to point --webhook-url at a Teams
	// channel's Incoming Webhook connector. The card's themeColor is derived from
	// the finding's confidence so a high-confidence leak shows red in the channel
	// at a glance.
	FormatTeams Format = "teams"
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
	case string(FormatTeams):
		return FormatTeams, nil
	default:
		return "", fmt.Errorf("unknown webhook format %q (want one of: json, slack, discord, teams)", s)
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
	case FormatTeams:
		return json.Marshal(teamsCard(f))
	default: // FormatJSON
		return json.Marshal(f)
	}
}

// teamsMessageCard is the minimal legacy "connector card" (MessageCard) shape a
// Microsoft Teams Incoming Webhook accepts. Only the always-present fields are
// modelled: a Teams card with @type/@context, a summary (required — Teams drops
// cards without one), a themeColor for the left accent bar, and the redacted
// text body. JSON field order/casing matches the keys Teams expects.
type teamsMessageCard struct {
	Type       string `json:"@type"`
	Context    string `json:"@context"`
	Summary    string `json:"summary"`
	ThemeColor string `json:"themeColor"`
	Text       string `json:"text"`
}

// teamsCard builds the MessageCard envelope for a finding. The body reuses the
// same redacted findingMessage summary every other chat format renders, so the
// never-emit-raw-secrets invariant holds for Teams too — only redacted/locator
// fields ever reach the card. The summary is a short, fixed redacted headline
// (Teams shows it in notifications and requires it to render the card at all),
// and themeColor maps the confidence score to an accent the responder reads at a
// glance.
func teamsCard(f output.Finding) teamsMessageCard {
	desc := f.RuleDesc
	if desc == "" {
		desc = f.RuleID
	}
	return teamsMessageCard{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		Summary:    "séance leak alert: " + desc,
		ThemeColor: confidenceColor(f.Confidence),
		Text:       findingMessage(f),
	}
}

// confidenceColor maps a finding's confidence to a 6-hex-digit themeColor for
// the Teams card accent bar: red for high-confidence leaks, amber for medium,
// grey for low. Thresholds mirror the confidence bands operators tune against
// --webhook-min-confidence. The value is the bare hex Teams expects (no leading
// '#').
func confidenceColor(confidence float64) string {
	switch {
	case confidence >= 0.85:
		return "D00000" // red — high confidence
	case confidence >= 0.5:
		return "E0A800" // amber — medium confidence
	default:
		return "6C757D" // grey — low confidence
	}
}

// findingMessage builds the human-readable, redacted one-message summary used by
// the Slack, Discord, and Teams envelopes. It composes only redacted/locator
// fields — rule, repo, file/line, the redacted value, confidence, and
// fingerprint — never any raw secret material.
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
