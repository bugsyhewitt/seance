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
| Optionally monitor the GitHub commit Search API for your keywords/orgs (`--watch`) | Access private repositories |
| Recover and scan secrets buried by a force-push (history rewrite) | Store or log raw secret values — findings are always redacted |
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

## Force-push detection

A force-push (`git push --force`) that rewrites history backward is the single
highest-signal indicator of an *intentional* secret removal: a developer commits
a key, notices, and rewrites the branch back to before the mistake. The leaked
secret then lives only in the commit(s) that became **dangling** between the
branch's old tip (`before`) and its new tip (`head`) — content that a tool which
only scans the new HEAD never sees.

séance detects the force-push shape from the push event (HEAD reset backward with
no new distinct commits, or the payload's `forced` flag) and recovers the
orphaned diff with a single `GET /repos/{owner}/{repo}/compare/{head}...{before}`
request. Dangling commits remain retrievable by SHA on GitHub for a window, which
is exactly long enough for séance to scan what someone tried to bury.

This is on by default and costs one extra compare request per force-push (force
pushes are rare relative to normal pushes, so the rate-limit impact is small).
Disable it with `--force-push=false`. The `force_pushes_total` metric reports how
many force-push events have been recovered.

```bash
# Default: force-push recovery enabled
seance

# Disable force-push recovery (saves one compare request per force-push)
seance --force-push=false
```

Branch creations (`before` is the all-zero SHA) and branch deletions (`head` is
the all-zero SHA) are *not* treated as force-pushes — there is no recoverable
prior tip.

---

## Targeted / org-scoped monitoring (`--watch`)

The global events stream is a *firehose of fresh pushes* — it is bounded by the
events endpoint's pagination depth and only sees what was pushed while séance was
listening. It misses leaks that already sit **indexed** in repos pushed before
séance started, in forks, and in commits whose push event scrolled off the
window. `--watch` adds a complementary coverage axis built on GitHub's commit
Search API:

```bash
# Watch your org name and an internal hostname (repeatable).
seance --watch acme-corp --watch internal.example.com
```

Each keyword is polled via `GET /search/commits`; matching commits flow into the
**same** pipeline as the events stream — prefilter, fetch, scan, dedup, redaction,
and every sink (NDJSON / TUI / webhook) are reused unchanged. Findings from this
provider carry `"provider": "search"` so you can tell the two coverage axes apart
downstream.

The Search API has its **own, much stricter quota** (30 requests/minute
authenticated; 10/minute unauthenticated) that is separate from the core 5,000
req/hr budget. séance's search provider governs its own cadence against that
ceiling — it polls conservatively (~90s sweeps) and backs off automatically when
`X-RateLimit-Remaining` runs low, recovering the moment the window resets. The
events stream is unaffected by this; the two providers run concurrently and
independently.

`--watch` is **off by default** — with no keywords the search provider is absent
entirely and the events-only path is unchanged. The
`search_requests_total`, `search_results_total`, `search_commits_total`, and
`search_rate_limit_remaining` metrics report its activity on the stderr metrics
line.

> A token is strongly recommended with `--watch`: the unauthenticated Search API
> quota (10 req/min) is barely usable for more than one keyword.

### Scoping the search window (`--watch-since` / `--watch-until`)

The events stream is inherently *now* — it only carries fresh pushes. The search
corpus is different: it is an **index of history**, so by default `--watch` will
keep re-surfacing the same ancient commits that match your keyword. Two optional
flags scope the search provider to a committer-date window so you see only the
slice of history you care about:

```bash
# Only commits pushed in the last week (suppress the ancient indexed backlog).
seance --watch acme-corp --watch-since 2026-05-22

# A targeted investigation: everything that matched in a fixed window.
seance --watch acme-corp --watch-since 2026-01-01 --watch-until 2026-03-01

# Open-ended on one side: everything up to and including a cutoff date.
seance --watch acme-corp --watch-until 2026-03-01
```

Dates are calendar days in `YYYY-MM-DD` form; the range is **inclusive** and
either bound may be set independently. The window is rendered into GitHub's
`committer-date:` search qualifier, so the **index** does the filtering — séance
issues no extra requests and never fetches commits outside the window. These
flags apply **only** to the `--watch` search provider; the global events stream
is unaffected. An invalid date, or a `--watch-since` later than `--watch-until`,
fails the run loudly rather than silently returning an unscoped firehose. Leaving
both unset preserves the prior behavior (the search corpus is unscoped).

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

# Load configuration from a TOML file instead of a long command line.
# Any flag you ALSO pass overrides the file (defaults < file < flags).
seance --config /etc/seance/seance.toml

# Custom signatures file
seance --signatures /path/to/rules.toml

# Hot-reload signatures into a running séance without a restart:
# edit the file, then send SIGHUP. The process keeps its ETag, poll
# cadence, and seen-commit dedup set — only the rules change.
kill -HUP $(pgrep -f '^seance')

# Disable force-push (history-rewrite) recovery
seance --force-push=false

# Targeted/org-scoped monitoring: ALSO poll the commit Search API for your
# keywords (repeatable). Runs alongside the global events stream.
seance --watch acme-corp --watch internal.example.com

# Scope the --watch search corpus to a committer-date window (YYYY-MM-DD) so it
# stops re-surfacing ancient indexed commits; either bound is optional.
seance --watch acme-corp --watch-since 2026-05-22
seance --watch acme-corp --watch-since 2026-01-01 --watch-until 2026-03-01

# Pipe findings to jq; metrics go to stderr so they don't mix
seance 2>seance.log | jq 'select(.confidence > 0.8)'

# Surface only high-confidence findings EVERYWHERE at once: --min-confidence is a
# global floor applied before any sink, so stdout, --output-file, --sarif-file,
# --tui, and the webhook all see only findings scoring at or above it. One dial to
# trade recall for precision when the firehose gets noisy.
seance --min-confidence 0.85

# Watch it work: a live, confidence-colored terminal feed instead of raw NDJSON.
# Falls back to NDJSON automatically when stdout is piped or redirected.
seance --tui

# Keep a durable, machine-readable record while watching the live feed: the TUI
# takes over stdout, --output-file captures every finding as NDJSON to a file.
seance --tui --output-file findings.ndjson

# Page a human channel in real time: POST every high-confidence finding
# to a webhook in addition to the stdout NDJSON stream.
seance \
  --webhook-url https://hooks.example.com/seance \
  --webhook-header "Authorization:Bearer $ALERT_TOKEN" \
  --webhook-min-confidence 0.85
```

### Configuration file (`--config`)

séance's intended deployment is a run-forever monitor under systemd or Docker. At
that point a 20-flag command line is brittle to manage and impossible to review.
`--config <path>` lets you express the entire configuration in one versioned TOML
file instead.

Precedence runs **defaults < file < flags/env** — built-in defaults are the base,
the file overlays them, and any flag you *also* pass on the command line overrides
the same field in the file. That means you can keep a stable file checked into
config management and still override one value ad hoc:

```bash
# Run from a file…
seance --config /etc/seance/seance.toml

# …but bump the poll interval just for this run; the flag wins over the file.
seance --config /etc/seance/seance.toml --poll-interval 30
```

Every flag has a corresponding snake_case key. Keys you omit keep their default;
unknown keys are a **hard error** (a misspelled `webhook_ur` should be reported,
not silently disable your alert channel), and a missing or unparseable file fails
the run rather than quietly falling back to defaults. The token can live in the
file (`github_token = "..."`) or, more safely, stay in the `GITHUB_TOKEN`
environment variable — the env var still applies on top of the file.

```toml
# /etc/seance/seance.toml — every key is optional; omit to keep the default.
poll_interval_sec = 30
force_push        = true
min_confidence    = 0.7              # global floor before any sink

# Targeted/org-scoped monitoring (alongside the global events stream)
watch             = ["acme-corp", "internal.example.com"]
watch_since       = "2026-01-01"

# Durable record + live feed
tui               = true
output_path       = "/var/log/seance/findings.ndjson"
sarif_path        = "/var/log/seance/findings.sarif"

# Real-time alerting
webhook_url            = "https://hooks.example.com/seance"
webhook_headers        = ["Authorization:Bearer REDACTED"]
webhook_min_confidence = 0.85
webhook_format         = "slack"

# Cross-run dedup / suppression
suppress_file = "/etc/seance/suppress.txt"
state_dir     = "/var/lib/seance"
seen_ttl_days = 7
```

No new dependency is introduced — the file is parsed with the same TOML library
séance already uses for signatures. The config file only ever holds configuration;
the never-store-raw invariant is untouched (séance still writes only redacted
findings to every sink).

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
  "timestamp": "2026-05-17T14:30:00Z",
  "fingerprint": "sha256:9b1e...c4"
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

The `fingerprint` field is a stable, privacy-preserving identifier for the whole
finding — a SHA-256 over `(rule_id, redacted, repo_owner, repo_name, file_path)`.
It is the cross-run deduplication key and the value you copy into a
`--suppress-file` to silence a known false positive (see
[Deduplication & suppression](#deduplication--suppression)). Because it is built
only from already-redacted/locator material, it never embeds raw secret bytes.

Raw secret material is never written to disk, logs, or any output. This is a
hard invariant, not a configuration option.

### Live terminal feed (`--tui`)

Running séance interactively, the raw NDJSON firehose is hard to read at a
glance. `--tui` swaps the stdout stream for a live wall: a scrolling list of the
most recent findings — colored by confidence (red high, yellow medium, green
low) — above running counters for total findings, distinct rules hit, and peak
confidence seen this session.

```bash
seance --tui
```

It is purely a presentation change to the primary output sink. Coverage,
deduplication, and webhook alerting are unaffected — the same `Finding` flows to
the same data path; only the stdout rendering differs.

**Graceful degradation.** A live ANSI feed only makes sense on an interactive
terminal. When stdout is *not* a TTY — a pipe, a redirect to a file, or CI —
`--tui` is silently ignored and séance writes plain NDJSON instead, so a
downstream `jq` or log store is never corrupted by escape sequences:

```bash
# --tui on a terminal: colored live feed.
seance --tui

# --tui piped: automatically falls back to NDJSON (a notice goes to stderr).
seance --tui | jq .
```

The TUI sink, like every séance sink, only ever renders the already-redacted
`Finding`; the never-emit-raw-secrets invariant is preserved unchanged.

### Durable output file (`--output-file`)

By default findings stream as NDJSON to stdout. `--output-file` *additionally*
appends every finding to a file on disk, independent of whatever stdout is doing.
The primary use is pairing it with `--tui`: the live feed owns stdout, so without
a file sink the machine-readable stream that `jq` or a SIEM loader needs has
nowhere to go. With `--output-file` you watch the colored wall **and** keep a
durable record at the same time:

```bash
# Live feed on the terminal, durable NDJSON record on disk — both at once.
seance --tui --output-file findings.ndjson

# Without --tui it is a simple tee: NDJSON to stdout for a live pipe AND to a file.
seance --output-file logs/seance.ndjson | jq 'select(.confidence > 0.9)'
```

| Flag | Description |
|------|-------------|
| `--output-file` | Append redacted NDJSON findings to this file in addition to stdout. The parent directory is created if missing. `-` or empty (default) means stdout only. |

Behavior and guarantees:

- **Same redacted body.** Each line is exactly the NDJSON `Finding` object shown
  in [Output format](#output-format). Because `Finding` has no raw field, the
  never-emit-raw-secrets invariant holds for the file for free — it can never
  contain a usable secret.
- **Append, never truncate.** The file is opened in append mode, so restarting
  séance extends the record instead of erasing prior findings.
- **Auto-created path.** A missing parent directory is created
  (`--output-file logs/seance.ndjson` works without a prior `mkdir`).

### SARIF report (`--sarif-file`)

[SARIF](https://sarif.info) (the OASIS *Static Analysis Results Interchange
Format*, 2.1.0) is the standard report format that GitHub Advanced Security /
code scanning, Azure DevOps, and most security viewers ingest. Pass
`--sarif-file` to *also* write a SARIF document of every finding the run
observed — turning séance's live stream into a report a security platform can
load, triage, and track.

```bash
# Stream NDJSON to stdout as usual AND write a SARIF report on shutdown.
seance --sarif-file scan.sarif

# Compose freely: live feed on the terminal, durable NDJSON on disk,
# and a SARIF report for your security platform — all at once.
seance --tui --output-file findings.ndjson --sarif-file reports/scan.sarif
```

| Flag | Description |
|------|-------------|
| `--sarif-file` | Write a SARIF 2.1.0 report of all findings to this file in addition to whatever else is configured. The parent directory is created if missing. Empty (default) disables the SARIF sink. |

Behavior and guarantees:

- **One document, written on shutdown.** Unlike the streaming NDJSON sinks, SARIF
  is a single document with a `runs[].results[]` array and a deduplicated
  `tool.driver.rules[]` catalog, so it is buffered in memory and written once when
  séance stops (Ctrl-C / SIGTERM). A clean run with zero findings still produces a
  valid empty-results report.
- **Same redacted body.** Each result is built solely from the redacted `Finding`
  — the redacted value and stable fingerprint land in `partialFingerprints`, the
  repo/commit/path in the result's artifact location, and séance's confidence in
  `properties`. Because `Finding` has no raw field, the never-emit-raw-secrets
  invariant holds for the SARIF report for free.
- **Confidence → level.** séance's 0–1 confidence maps onto SARIF's `result.level`:
  `≥ 0.8` → `error`, `≥ 0.5` → `warning`, otherwise `note`.
- **Atomic write.** The report is written via a temp file and renamed into place,
  so a crash mid-write never leaves a half-written document a SARIF consumer would
  reject. The parent directory is auto-created (`--sarif-file reports/scan.sarif`
  works without a prior `mkdir`).

### Webhook alerting

A monitor nobody is watching is useless. By default séance writes NDJSON to
stdout; pass `--webhook-url` to *also* POST each finding to an HTTP endpoint so
alerts reach a human channel (your own relay, a SIEM, a chat-bridge service) the
moment they happen.

```bash
seance \
  --webhook-url https://hooks.example.com/seance \
  --webhook-header "Authorization:Bearer $ALERT_TOKEN" \
  --webhook-min-confidence 0.85
```

| Flag | Description |
|------|-------------|
| `--webhook-url` | Endpoint each finding is `POST`ed to as JSON. Empty (default) disables the webhook sink. |
| `--webhook-header KEY:VALUE` | Header added to every request. **Repeatable.** Only the first `:` is the separator, so values may contain colons (e.g. `Authorization:Bearer x:y`). |
| `--webhook-min-confidence` | Only findings with `confidence` at or above this value (0.0–1.0) are sent. Defaults to `0` (alert on everything). Tune it against the confidence score to trade recall for signal. |
| `--webhook-format` | POST body shape: `json` (the redacted `Finding` object, default), `slack`, or `discord`. `slack`/`discord` render the redacted finding into the message envelope each platform's incoming webhook expects, so `--webhook-url` can point straight at a Slack or Discord webhook with no relay. An unknown value fails the run at startup. |

#### Slack & Discord (`--webhook-format`)

The default `json` body is the raw redacted `Finding` — ideal for a custom relay
or a SIEM. But the two channels operators most want to page, **Slack** and
**Discord**, do not accept an arbitrary JSON object: each incoming webhook
expects a specific message envelope (`{"text": …}` for Slack, `{"content": …}`
for Discord). Pointing `--webhook-url` straight at a Slack/Discord webhook with
the default body produces a silent rejection and no alert.

`--webhook-format slack` (or `discord`) renders each finding into the envelope
the target platform expects — a short, human-readable, **fully redacted**
summary (rule, repo, file/line, the redacted value, confidence, fingerprint) —
so you can wire the webhook directly with no relay in between:

```bash
# Page a Slack channel directly — no relay service needed.
seance \
  --webhook-url https://hooks.slack.com/services/T000/B000/XXXX \
  --webhook-format slack \
  --webhook-min-confidence 0.85

# Or a Discord channel.
seance \
  --webhook-url https://discord.com/api/webhooks/000/XXXX \
  --webhook-format discord
```

The `slack`/`discord` envelopes carry only the same redacted/locator fields as
every other sink — the never-emit-raw-secrets invariant holds for them too. The
default (`json`) body is unchanged, so existing endpoints keep working.

Behavior and guarantees:

- **Same body, fully redacted.** The default JSON POST body is exactly the NDJSON `Finding`
  object shown above. Because `Finding` has no raw field, the never-emit-raw-
  secrets invariant holds for the webhook for free — and equally for the
  `slack`/`discord` envelopes, which render only redacted fields.
- **Content type** is `application/json`; configured headers are applied to every
  request.
- **Non-blocking.** Findings are handed to a bounded in-memory queue drained by a
  background worker. A slow or hung endpoint can never apply backpressure to the
  scanner. If the queue fills, overflow findings are dropped and counted rather
  than stalling the pipeline.
- **Fail open.** A non-2xx response or transport error is logged to stderr and
  the run continues — a dead alerting channel never takes down the monitor.
- **Observable.** The stderr metrics line gains `alerts_sent_total`,
  `alerts_failed_total`, and `alerts_dropped_total` so you can see delivery
  health at a glance.

Built-in `slack` and `discord` formats (see `--webhook-format` above) cover the
two channels operators reach for most, with no relay required. Other targets
(Telegram, a bespoke SIEM shape) can still sit as a thin relay in front of the
default `json` body, or land later as additional formats — the output layer fans
out to any number of sinks.

### Inbound webhook receiver (`--webhook-listen`)

For the lowest possible latency — and zero polling/rate-limit cost — séance can
act as the **receiving** end of a GitHub push webhook instead of (or alongside)
polling the public events stream.

```bash
seance \
  --token $GITHUB_TOKEN \
  --webhook-listen :8099 \
  --webhook-listen-secret $GITHUB_WEBHOOK_SECRET
```

Configure the GitHub webhook to deliver `push` events to
`http(s)://<your-host>:8099/webhook`. Every delivery is scanned the instant it
arrives — no poll interval, no Events API quota consumed.

`--webhook-listen` is **additive**: it fans `CommitEvents` into the same pipeline
as the global events stream and `--watch`. All existing sinks (stdout NDJSON, TUI,
`--output-file`, `--sarif-file`, `--webhook-url`) receive findings from inbound
webhooks exactly like any other source.

#### HMAC verification (`--webhook-listen-secret`)

When `--webhook-listen-secret` is set, séance verifies every delivery's
`X-Hub-Signature-256` header before parsing the body. Set the same value in the
GitHub webhook **Secret** field. Deliveries with a missing or incorrect signature
are rejected with `403 Forbidden` — the body is never read.

Running without a secret is allowed (private-network or sidecar deployments where
the listener is not internet-facing) but séance logs a warning at startup.

| Flag | Description |
|---|---|
| `--webhook-listen ADDR` | TCP address to listen on, e.g. `:8099` or `127.0.0.1:8099`. Empty (default) disables the receiver. |
| `--webhook-listen-secret SECRET` | HMAC-SHA256 secret matching the GitHub webhook Secret field. Empty skips signature verification (with a logged warning). |

### Deduplication & suppression

At firehose volume, alert fatigue is the failure mode that gets a monitor turned
off. An alerting tool without deduplication is a spam cannon. séance dedups
*findings*, not just commits: the same secret re-committed across forks,
re-pushed after a restart, or matched by two overlapping rules is alerted **once**.

Every finding carries a stable `fingerprint` (see [Output format](#output-format))
derived only from `(rule_id, redacted, repo_owner, repo_name, file_path)` — so
identical secrets in the same place collide correctly without ever touching raw
material. There are two suppression layers:

- **Cross-run re-leak suppression (always on, no flag).** Each emitted finding's
  fingerprint is recorded in the persistent state file (`<state-dir>/state.json`,
  alongside the seen-commit set) and evicted on the same rolling TTL. A finding
  whose fingerprint was already seen — this run or a prior one — is suppressed
  instead of re-alerting.
- **Operator suppress-list (`--suppress-file`).** A newline-delimited list of
  fingerprints to *always* ignore — the `.gitleaksignore` analogue. Copy a
  finding's `fingerprint` into the file to silence a known false positive. Blank
  lines and `#` comments are allowed. Suppress-list entries are never recorded as
  "seen", so removing one re-enables alerting immediately.

```bash
# A known false positive keeps firing — grab its fingerprint from the NDJSON
# and drop it into a suppress file:
echo "sha256:9b1e...c4  # test fixture key, not a real leak" >> seance.ignore
seance --suppress-file seance.ignore
```

| Flag | Description |
|------|-------------|
| `--suppress-file` | Path to a newline-delimited list of finding fingerprints to always ignore. `#` comments and blank lines are skipped. Empty (default) means only known re-leaks are suppressed. |

The `findings_suppressed_total` metric counts how many findings were dropped by
either layer, and `seen_findings_tracked` reports the current size of the
persistent fingerprint set. Because the dedup key is the privacy-preserving
fingerprint, persisting it can never leak a credential — the never-store-raw
invariant holds for free.

### Confidence floor (`--min-confidence`)

Dedup removes *repeats*; the confidence floor removes *low-signal* findings. Every
finding carries a `confidence` score in `[0.0, 1.0]` (see [Output
format](#output-format)) computed from rule specificity, entropy headroom, and
path weight. `--min-confidence` is a **global floor**: any finding scoring below it
is dropped before it reaches **any** sink — stdout/NDJSON, `--output-file`,
`--sarif-file`, `--tui`, and the webhook all see the identical filtered set. It is
the single dial that trades recall for precision across the whole tool, so a noisy
firehose can be tightened to only the findings worth a human's attention with one
flag.

```bash
# Only surface findings the scorer is confident about — everywhere at once.
seance --min-confidence 0.85

# Compose with the live feed and a durable record: both honor the same floor.
seance --tui --output-file findings.ndjson --min-confidence 0.8
```

| Flag | Description |
|------|-------------|
| `--min-confidence` | Global confidence floor (`0.0`–`1.0`). Findings below it are dropped before every sink. Defaults to `0` (emit everything — unchanged behavior). Out-of-range values are rejected at startup. |

The floor is applied **before** deduplication and the sink fan-out, so a
sub-threshold finding never consumes a dedup slot and never reaches output — the
never-store-raw invariant holds on the drop path too (nothing is emitted at all).
The `findings_below_confidence_total` metric counts how many findings the floor
dropped, so the trade-off is observable.

> **Floor vs. webhook gate.** `--min-confidence` is engine-wide; `--webhook-min-confidence`
> ([Webhook alerting](#webhook-alerting)) gates only the webhook channel and is
> applied *on top of* the floor. Use the floor to set a baseline for all output and
> the webhook gate to page on an even higher bar.

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
- An `allowlist` block for known test/dummy values

### Built-in coverage

The shipped `signatures/default.toml` detects the high-prevalence credential
types seen in real public-repo leaks:

- **Cloud** — AWS access key IDs and secret access keys, Google API keys
- **Version control** — GitHub PATs (classic, OAuth, app, fine-grained)
- **Payments** — Stripe secret and restricted keys
- **Messaging / email / SMS** — Slack bot/user tokens and webhooks, SendGrid,
  Twilio
- **AI / LLM providers** — OpenAI (legacy `sk-` and project/service
  `sk-proj-`/`sk-svcacct-`), Anthropic (`sk-ant-`), and Hugging Face (`hf_`)
  tokens — the fastest-growing class of leaked credential in the 2024–2026
  landscape, where a live key bills the victim's account directly
- **Crypto** — PEM and PGP private-key blocks
- **Generic** — a high-entropy `api_key = "…"` catch-all for everything else

Each rule matches the issuer's documented, structurally-unambiguous prefix shape
(no broad catch-alls beyond the explicit generic rule) and most carry an entropy
gate, so the global placeholder filter and confidence score keep false positives
low out of the box.

### Allowlists

Every rule may carry an `allowlist` block — the gitleaks-standard mechanism for
suppressing matches a rule author knows are false positives. séance honors all
four allowlist axes:

```toml
[[rules]]
  id          = "aws-access-key-id"
  description = "AWS Access Key ID"
  regex       = '''AKIA[A-Z0-9]{16}'''
  keywords    = ["AKIA"]

  [rules.allowlist]
    # Literal substrings — match anywhere in the matched value.
    stopwords = ["EXAMPLE", "changeme", "placeholder"]
    # Value regexes — suppress a whole *shape* of false positive without
    # listing every literal (e.g. any AWS key ending in EXAMPLE).
    regexes   = ['''AKIA[A-Z0-9]{9}EXAMPLE''']
    # Path regexes — exempt entire files (test fixtures, vendored dirs, docs).
    # A matching path suppresses every finding the rule would make in that file.
    paths     = ['''(^|/)testdata/''', '''_test\.go$''']
    # Commit SHAs — accept a reviewed commit's matches. Prefix-tolerant and
    # case-insensitive: a short SHA matches the full commit SHA, like Git.
    commits   = ["deadbeef"]
```

- **`stopwords`** — literal substrings; if any appears in the matched value, the
  match is dropped.
- **`regexes`** — patterns tested against the matched value; a match is dropped.
- **`paths`** — patterns tested against the file path; a matching file is exempt
  from the rule entirely.
- **`commits`** — commit SHAs (full or abbreviated) whose matches are accepted.

Allowlists are **fail-safe**: a malformed `regexes`/`paths` pattern is skipped,
never treated as a universal match, so a typo can never silently disable
detection. Allowlists scope a rule's false positives at authoring time;
`--suppress-file` (see [Deduplication & suppression](#deduplication--suppression))
silences individual findings at runtime without editing the ruleset.

### Global placeholder / dummy-value filter (always on)

Documentation samples, tutorial stand-ins, and manual masks are the single
largest class of false positive at firehose scale, and they recur across *every*
credential type — `AKIAIOSFODNN7EXAMPLE`, `your_api_key`, `ghp_000…000`,
`AKIAAAAAAAAAAAAAAAAA`. Enumerating them in every rule's `stopwords` is
impractical, so séance applies one **global placeholder filter** to every match,
after the entropy gate and before a finding is emitted. A candidate value is
dropped if it carries an unmistakable placeholder signature:

- a known placeholder word (case-insensitive substring) — `example`,
  `placeholder`, `changeme`, `your_key` / `your_api_key`, `insert_key`,
  `dummy_key`, `redacted`, `lorem` …; or
- a run of the same character repeated 8+ times (a manual mask); or
- a textbook sequential-hex or full-alphabet fill.

The filter is deliberately **conservative**: precision is weighted far above
recall, because suppressing a *real* leak is the catastrophic failure and a
surviving dummy is merely noise the entropy gate and confidence score already
temper. A randomly generated credential never carries these signatures, so it is
never dropped. The check runs only on the in-memory candidate value — nothing
raw is logged, persisted, or emitted, exactly like the entropy gate — and every
drop is counted in the `placeholders_dropped_total` metric.

A rule that *legitimately* matches placeholder-shaped values can opt out by
adding the `no-placeholder-filter` tag:

```toml
[[rules]]
  id       = "intentional-sample-detector"
  regex    = '''…'''
  keywords = ["…"]
  tags     = ["no-placeholder-filter"]   # bypass the global placeholder filter
```

### Validating a ruleset (`seance rules validate`)

The scan engine is **fail-safe by design**: a rule whose `regex` does not
compile — or an allowlist whose `regexes`/`paths` pattern does not compile — is
*silently skipped* at scan time. That is the right runtime behaviour (a bad edit
must never crash a monitor you've left running for days), but it has a sharp
edge: a typo silently disables detection, and the only symptom is a quiet stream
of zero findings you might not notice for days.

`seance rules validate` is the **pre-flight check** that surfaces those defects
*before* you deploy a ruleset, so you learn at edit time, not from a silent gap
in coverage:

```bash
# Validate the default --signatures file (no argument needed).
seance rules validate

# Validate a specific file.
seance rules validate my-rules.toml

# Validate every *.toml in a directory.
seance rules validate signatures/
```

It reports the exact defects the engine would tolerate at runtime:

- a rule whose `regex` is empty or does not compile (**error** — silently
  skipped at scan time)
- an `allowlist` `regexes`/`paths` pattern that does not compile (**error** —
  silently skipped, so the false positive it was meant to suppress fires)
- a missing or duplicate rule `id` (**error**)
- a `secretGroup` that is negative or exceeds the regex's capture-group count
  (**error** — the engine would fall back to the full match and redact too much)
- a rule with no `keywords` (**warning** — its regex runs against every line, a
  performance and false-positive hazard) or an impossible `entropy` floor
  (**warning** — the rule can never fire)

Example output against a ruleset with a typo:

```
my-rules.toml: 4 rule(s), 1 error(s), 1 warning(s)
  ERROR: [aws-access-key-id] regex: regex does not compile (the engine silently skips this rule at runtime): error parsing regexp: missing closing ]
  WARNING: [generic-key] keywords: rule has no keywords; its regex runs against every line (slower, noisier).
```

Exit status makes it CI-friendly: **0** when there are no errors (warnings alone
do not fail), **1** when any error is found, **2** when a file cannot be read or
parsed. Drop `seance rules validate signatures/` into a pre-commit hook or CI
step to catch a broken rule before it ever reaches a running monitor.

### Hot-reload (SIGHUP)

séance is built to run for days. When you add or tune a rule, you should not
have to restart it — even though the ETag now survives a restart, a restart
still drops the warm rate-limit/poll-cadence state and interrupts the stream.
Instead, edit the signatures file in place and send the process `SIGHUP`:

```bash
# Edit your rules...
vim my-rules.toml

# ...validate the edit before it goes live (catches a broken regex the running
# monitor would otherwise silently skip)...
seance rules validate my-rules.toml

# ...then reload them into the running process.
kill -HUP <pid>
```

séance re-reads the **same** `--signatures` path it was started with and swaps
the active rule set atomically. The poll loop, ETag, seen-commit dedup set, and
metrics counters all continue uninterrupted; an in-flight scan finishes against
the rules it started with, and the next scan uses the new set.

Reloads are **fail-safe**: if the file is missing, contains invalid TOML, or
parses to zero rules, séance logs the problem to stderr and **keeps the
currently active rules**. A typo in an edit can never silence a running monitor.
A successful reload logs the new rule count:

```
séance: SIGHUP reload — loaded 18 rules from signatures/default.toml
```

---

## State

séance persists a small state file under `.seance/` (configurable with
`--state-dir`). This stores:
- **Seen-commit set**: SHA map for deduplication, 7-day rolling TTL
  (`seen_ttl_days`, default 7). A background sweep evicts entries older than
  the window every 5 minutes — and once more on shutdown — so the set and the
  on-disk state file stay bounded for the life of the process. Reloaded on
  restart — no duplicate findings across restarts.
- **Seen-finding set**: a map of finding fingerprints to first-seen time,
  evicted on the same rolling TTL. This is what suppresses cross-run re-leaks
  (see [Deduplication & suppression](#deduplication--suppression)). It stores
  only the privacy-preserving fingerprint, never raw secret material. Reloaded
  on restart so a re-pushed secret is not re-alerted across a restart.
- **ETag**: the last GitHub events ETag, used for conditional polling
  (`If-None-Match` → HTTP 304 when nothing new happened). It is now persisted
  to the state file and reloaded on restart, so the **first poll after a restart
  is a conditional request, not a full cold fetch** — a restart no longer
  re-pulls and re-prefilters the whole events page. If the cursor has expired
  server-side, GitHub simply answers 200 with a fresh page and a new ETag, so
  there is no correctness impact either way.

On first run séance starts fresh. On SIGINT/SIGTERM it flushes state and
exits 0. On SIGHUP it hot-reloads the signatures file without exiting (see
[Hot-reload](#hot-reload-sighup)). Deleting `.seance/` resets state completely.

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
4. Force-push recovery adds one `GET /compare` request *per force-push only*.
   Force-pushes are rare relative to normal pushes, so the budget impact is
   minor; disable with `--force-push=false` if you need the headroom.

Observed in validation (off-peak): ~1,475 requests/hour — roughly 29% of budget.

Live metrics are written to stderr every 60 s in `key=value` format:

```
séance metrics ts=1234567890 push_events_total=454 force_pushes_total=3 \
  prefilter_passed_total=405 prefilter_dropped_total=49 fetches_total=405 \
  polls_total=17 findings_total=0 findings_suppressed_total=2 \
  findings_below_confidence_total=4 placeholders_dropped_total=11 \
  seen_commits_tracked=412 seen_findings_tracked=6 \
  push_events_hr=1602.3 prefilter_survival_pct=89.2 fetches_hr=1429.3 \
  polls_hr=60.0 rate_limit_remaining=4592 rate_limit_reset_in=1981
```

`force_pushes_total` counts force-push (history-rewrite) events detected and
recovered via the compare API (see [Force-push detection](#force-push-detection)).

`seen_commits_tracked` is the current size of the seen-commit dedup set. It
stays bounded by the 7-day TTL (see [State](#state)): a background sweep evicts
entries older than the window every 5 minutes, and a final sweep runs on
shutdown before the state file is persisted.

`findings_suppressed_total` counts findings dropped by cross-run dedup or the
operator suppress-list, and `seen_findings_tracked` is the current size of the
persistent fingerprint set — both bounded by the same TTL (see
[Deduplication & suppression](#deduplication--suppression)).

`findings_below_confidence_total` counts findings dropped by the global
`--min-confidence` floor before they reached any sink (see
[Confidence floor](#confidence-floor---min-confidence)). It stays at `0` unless a
floor is set.

`placeholders_dropped_total` counts matches dropped by the global
placeholder/dummy-value filter — documentation samples, masks, and `your_key`
stand-ins suppressed before they ever became findings (see
[Global placeholder / dummy-value filter](#global-placeholder--dummy-value-filter-always-on)).

Multiple tokens on one GitHub account do **not** raise the ceiling — the
5,000/hr limit is per account, not per token.

---

## License

MIT. See [LICENSE](LICENSE).

The default signatures are derived from the
[gitleaks ruleset](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
(MIT), adapted for the séance format. Do not add TruffleHog detectors —
TruffleHog is AGPL-3.0, which would contaminate this project's license.
