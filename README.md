# séance

> *Listening to what the dead repos whisper.*

séance watches the GitHub public commit stream and surfaces leaked credentials —
API keys, tokens, private keys, `.env` files — as fast as the source API allows.

It is a modern revival of the abandoned [shhgit](https://github.com/eth0izzle/shhgit),
rewritten in Go with an honest ingestion model, a pluggable gitleaks-compatible
ruleset, and a responsible-use posture baked in.

Part of the graveyard toolkit alongside
[graverobber](https://github.com/bugsyhewitt/graverobber),
[possession](https://github.com/bugsyhewitt/possession),
[exhumed](https://github.com/bugsyhewitt/exhumed), and
[unearth](https://github.com/bugsyhewitt/unearth).

---

## What it does / What it doesn't

| Does | Doesn't |
|------|---------|
| Watch the GitHub public events API for new pushes | Access private repositories |
| Surface file paths and commits containing leaked credentials | Store or log raw secret values — findings are always redacted |
| Apply a pluggable, gitleaks-compatible signature ruleset | Verify credentials against their provider APIs |
| Emit structured NDJSON findings for downstream processing | Scan retroactively (use GH Archive mode in a later release) |
| Operate within GitHub's API rate limits via pre-filtering | Claim to catch every leaked secret — it sees a subset of pushes |

### Latency — be honest about this

séance is **fast, not instant**. The GitHub public events API is explicitly
documented as not a real-time feed. Expect:

- **Typical**: 5–15 minutes from push to detection
- **Worst case**: Up to a few hours during API delays
- **Coverage**: ~15% of public push events at a time (rate-limit constraint)

The value is catching secrets before they are exploited, not before the
developer notices the typo. Many leaked credentials persist for days or weeks.

---

## Install

```bash
go install github.com/bugsyhewitt/seance/cmd/seance@latest
```

Or build from source:

```bash
git clone https://github.com/bugsyhewitt/seance
cd seance
make build
./seance --help
```

---

## Usage

```bash
# Watch the public stream with a GitHub token (required for sane rate limits)
seance --token ghp_your_token_here

# Use a custom signatures file
seance --token $GITHUB_TOKEN --signatures /path/to/rules.toml

# Pipe findings to jq
seance --token $GITHUB_TOKEN | jq 'select(.confidence > 0.8)'
```

### Output format

Each finding is one JSON line (NDJSON):

```json
{
  "rule_id": "aws-access-key-id",
  "rule_description": "AWS Access Key ID",
  "provider": "github",
  "repo_owner": "example-user",
  "repo_name": "my-project",
  "commit_sha": "abc123def456",
  "file_path": "config/prod.env",
  "line_number": 12,
  "redacted": "AKIA********************WXYZ",
  "confidence": 0.95,
  "tags": ["cloud", "aws"],
  "timestamp": "2026-05-17T14:30:00Z"
}
```

The `redacted` field shows the first and last 4 characters of the matched
value with stars in between — enough to confirm the type and rotate the right
secret, never enough to reconstruct it.

---

## Signatures

Signatures live in `signatures/default.toml` in the
[gitleaks TOML format](https://github.com/gitleaks/gitleaks) (MIT-licensed).
You can add custom rules or replace the file entirely:

```bash
seance --signatures my-rules.toml
```

Community contributions to `signatures/` are welcome. Please include:
- An `id` that is stable and unique
- A `description` that names the credential type
- `keywords` for fast pre-scan matching
- An `allowlist.stopwords` block for known test/dummy values

---

## State

séance persists a small state file under `.seance/` (configurable with
`--state-dir`). This stores:
- ETag cache for conditional polling (avoids re-processing)
- Seen-commit set for deduplication (7-day rolling window by default)
- Poll cursor for resuming after restart

On first run, séance starts fresh. On subsequent runs, it resumes from
the last cursor. Deleting `.seance/` resets state.

---

## Responsible use

séance finds **other people's** leaked credentials. This comes with
obligations:

- **Never use a discovered credential.** Authenticating with someone else's
  key without authorization is unauthorized access, full stop — regardless of
  how you found it.
- **This is a monitor, not a harvester.** Use findings for responsible
  disclosure to affected repo owners, internal alerting, or security research.
  Do not build a credential database.
- **séance does not verify findings.** It pattern-matches — it does not
  authenticate against provider APIs to confirm a key is live. Treat all
  findings as unverified until the owner confirms.
- **False positives happen.** High-entropy strings in test code, sample
  configs, and documentation frequently match patterns. Investigate before
  disclosing.
- **Respect GitHub's Terms of Service.** Automated access to the public API
  is permitted; building tools that facilitate unauthorized access is not.

If you discover a leaked credential, the responsible path is to notify the
repository owner privately, not to publicize the key.

---

## Rate limits

séance is designed to operate politely within GitHub's API limits:

- Authenticated: 5,000 requests/hour (one GitHub account)
- Unauthenticated: 60 requests/hour (not suitable for continuous use)

The pre-filter stage discards ~85% of commits before making any fetch
requests, keeping séance well within budget (~960 req/hr typical).

Multiple tokens on one GitHub account do **not** raise the ceiling — the
5,000/hr limit is per account, not per token.

---

## License

MIT. See [LICENSE](LICENSE).

The default signatures are derived from the
[gitleaks ruleset](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
(MIT), adapted for the séance format. Do not add TruffleHog detectors —
TruffleHog is AGPL-3.0, which would contaminate this project's license.
