# séance

> *Listening to what the dead repos whisper.*

séance watches the GitHub public commit stream and surfaces leaked credentials —
API keys, tokens, private keys, `.env` files — as fast as the source API allows

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

- **Typical**: 5–30 minutes from push to detection
- **Worst case**: Hours during API delays
- **Coverage**: a delayed, bounded subset of public push activity — bounded by
  the events endpoint's pagination depth (max ~300 events per poll window).
  The exact fraction of total GitHub push traffic is unknown and not published
  by GitHub. Run with `--token` and watch the live metrics output for real
  throughput numbers in your environment.

The value is catching secrets before they are exploited, not before the
developer notices the typo. Many leaked credentials persist for days or weeks.

---

## Install

**Binary** (recommended): download the pre-built binary for your platform from the
[releases page](https://github.com/bugsyhewitt/seance/releases/latest) and place it
on your `PATH`.

**Go install** (requires Go 1.26+):

```bash
go install github.com/bugsyhewitt/seance/cmd/seance@v0.1.0
```

**Docker**:

```bash
docker pull ghcr.io/bugsyhewitt/seance:v0.1.0
docker run --rm -e GITHUB_TOKEN=$GITHUB_TOKEN ghcr.io/bugsyhewitt/seance:v0.1.0
```

**Build from source**:

```bash
git clone https://github.com/bugsyhewitt/seance
cd seance
make build
./seance --help
```

---

## Usage

```bash
# Watch the public stream — token required for sane rate limits.
# Pass via flag or GITHUB_TOKEN environment variable.
export GITHUB_TOKEN=ghp_your_token_here
seance

# Explicit flag (overrides env var)
seance --token ghp_your_token_here

# Custom signatures file
seance --signatures /path/to/rules.toml

# Pipe findings to jq; metrics go to stderr so they don't mix
seance 2>seance.log | jq 'select(.confidence > 0.8)'
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
  "redacted": "sha256:3f2a1b9c",
  "confidence": 0.95,
  "tags": ["cloud", "aws"],
  "timestamp": "2026-05-17T14:30:00Z"
}
```

The `redacted` field is a stable identifier for the matched value, never the
value itself:

- **Short secrets (< 24 chars)**: a truncated SHA-256 fingerprint (`sha256:XXXXXXXX`).
  Exposing the first and last 4 characters of a 12-char secret would hand over
  most of the entropy, so séance uses a fingerprint instead. The owner can verify
  which credential leaked by hashing it locally.
- **Long secrets (≥ 24 chars)**: `<first4>********************<last4>` — enough
  to confirm which key to rotate without revealing usable material.

Raw secret material is never written to disk, logs, or any output. This is a
hard invariant, not a configuration option.

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
- **Seen-commit set**: SHA map for deduplication, 7-day rolling window.
  Reloaded on restart — no duplicate findings across restarts.
- **ETag**: cached in memory within a run for conditional polling (HTTP 304).
  Resets on restart; the first poll after restart is a full fetch, then
  conditional requests resume. One extra API call, no correctness impact.

On first run séance starts fresh. On SIGINT/SIGTERM it flushes state and
exits 0. Deleting `.seance/` resets state completely.

---

## Responsible use

séance finds **other people's** leaked credentials. This is a research and
monitoring tool. Using it carries firm obligations.

**Never use a discovered credential.** Authenticating with someone else's key
without authorization is unauthorized access — full stop, regardless of how
you found it and regardless of whether the credential is still active.

**The only correct response to a finding is responsible disclosure.** Contact
the repository owner privately. Give them time to rotate the credential before
any public disclosure. Do not publish the key, do not post it, do not share it.

**Do not build a credential database.** séance is a monitor. Accumulating
findings and indexing them by owner, service, or credential type turns a
monitoring tool into an attack resource. That is not what this is for.

**séance does not verify findings.** It pattern-matches — it does not
authenticate against provider APIs to confirm a key is live. All findings are
unverified until the owner confirms. Treat them accordingly.

**False positives are common.** Test keys, sample configs, tutorials, and
documentation frequently contain strings that match credential patterns.
Investigate before disclosing.

**séance redacts findings to protect you and the owner.** The `redacted`
field is a fingerprint or masked value — it is never the raw secret. This
is intentional. séance cannot be used to harvest usable credentials from its
own output. If you find yourself wanting to reconstruct the raw value from a
finding, stop.

**Respect GitHub's Terms of Service.** Automated access to the public events
API is permitted. Building tools that facilitate unauthorized access is not.

---

## Rate limits

séance is designed to operate politely within GitHub's API limits:

- **Authenticated**: 5,000 requests/hour (per GitHub account)
- **Unauthenticated**: 60 requests/hour — not viable for continuous use

**How séance stays within budget:**

1. Bot-author filter drops ~12% of push events before any API call.
2. One `GET /commits/{sha}` request per surviving push event retrieves all
   changed files. Post-fetch path filtering then discards commits with no
   suspicious extensions or segments.
3. Adaptive backoff fires when `X-RateLimit-Remaining` drops below 10%,
   widening the poll interval to 5 minutes until the window resets.

Observed in validation (off-peak): ~1,475 requests/hour — roughly 29% of budget.

Live metrics are written to stderr every 60 s in `key=value` format:

```
séance metrics ts=1234567890 push_events_total=454 prefilter_passed_total=405 \
  prefilter_dropped_total=49 fetches_total=405 polls_total=17 findings_total=0 \
  push_events_hr=1602.3 prefilter_survival_pct=89.2 fetches_hr=1429.3 \
  polls_hr=60.0 rate_limit_remaining=4592 rate_limit_reset_in=1981
```

Multiple tokens on one GitHub account do **not** raise the ceiling — the
5,000/hr limit is per account, not per token.

---

## License

MIT. See [LICENSE](LICENSE).

The default signatures are derived from the
[gitleaks ruleset](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
(MIT), adapted for the séance format. Do not add TruffleHog detectors —
TruffleHog is AGPL-3.0, which would contaminate this project's license.
