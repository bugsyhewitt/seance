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

### Tuning the search cadence (`--watch-interval`)

The `--watch` search provider polls every **90 seconds** by default — a cadence
chosen to keep a multi-keyword watch list comfortably inside the Search API's
strict authenticated quota (30 requests/minute), since each poll issues one
request *per keyword*. `--watch-interval` lets you tune that cadence in seconds:

```bash
# A single-keyword targeted investigation — poll faster for lower latency.
seance --watch acme-corp --watch-interval 20

# A long-running background monitor sharing a token — poll slower to leave
# Search-API budget for other clients.
seance --watch acme-corp --watch internal.example.com --watch-interval 300
```

This applies **only** to the `--watch` search provider; the global events stream
keeps its own cadence (`--poll-interval`). Values below a **10-second floor** are
clamped up — with a one-line stderr warning — because polling faster would burn
the 30 req/min quota almost immediately and trap séance in perpetual rate-limit
backoff. `0` (the default) keeps the conservative 90s cadence. The separate
low-budget backoff and two-way rate-limit recovery are unchanged, so tuning the
interval never weakens séance's quota protection. The override has no effect when
`--watch` is not configured.

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

# Tune the --watch search cadence (seconds). Default 90s; values below 10s are
# clamped up to protect the 30 req/min Search-API quota. Events stream unaffected.
seance --watch acme-corp --watch-interval 20

# Pipe findings to jq; metrics go to stderr so they don't mix
seance 2>seance.log | jq 'select(.confidence > 0.8)'

# CI gate: fail the build the moment a single finding lands. The cap is engine-
# wide, so stdout, --output-file, --sarif-file, --tui, and the webhook all see
# the same first-N findings, then séance shuts down cleanly (exit 0).
seance --output-limit 1

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
include_tags      = ["aws", "gcp"]   # only these credential classes reach any sink
exclude_tags      = ["generic"]      # drop this class everywhere (wins over include)

# Targeted/org-scoped monitoring (alongside the global events stream)
watch              = ["acme-corp", "internal.example.com"]
watch_since        = "2026-01-01"
watch_interval_sec = 90              # --watch poll cadence; 0 keeps the default

# Durable record + live feed
tui               = true
output_path       = "/var/log/seance/findings.ndjson"
output_max_bytes  = 26214400          # rotate at 25 MiB; 0 appends forever
output_limit      = 0                 # stop after N findings; 0 = unlimited (default)
sarif_path        = "/var/log/seance/findings.sarif"
csv_path          = "/var/log/seance/findings.csv"  # spreadsheet/ticketing export written on shutdown

# Real-time alerting
webhook_url            = "https://hooks.example.com/seance"
webhook_headers        = ["Authorization:Bearer REDACTED"]
webhook_min_confidence = 0.85
webhook_format         = "slack"

# Cross-run dedup / suppression
suppress_file        = "/etc/seance/suppress.txt"
state_dir            = "/var/lib/seance"
seen_ttl_days        = 7
dedupe_window_days   = 0              # 0 = inherit seen_ttl_days; >0 tunes finding dedup independently

# Global outbound throttle
rate_limit    = 0                     # aggregate req/s cap across every HTTP surface; 0 = no cap
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

### Choosing the stdout stream (`--output`)

`--output` selects how findings are streamed to **stdout**. Two streaming
formats are available:

| `--output` | Stream |
|---|---|
| `json` (default) | Newline-delimited JSON (NDJSON) — one `Finding` object per line, the format shown above. Ideal for `jq`, log stores, and SIEM ingestion. |
| `text` | One compact, human-readable line per finding. Grep- and `awk`-friendly, easy to eyeball while tailing the feed, without the NDJSON verbosity or the full-screen `--tui` takeover. |

A `text` line looks like:

```
[HIGH] rule=aws-access-key repo=alice/repo file=config/prod.env:12 conf=0.90 redacted=AKIA****WXYZ fp=sha256:9b1e...c4
```

The leading `[HIGH]` / `[MED]` / `[LOW]` tag buckets the finding by confidence
(the same thresholds the SARIF severity mapping uses), so `seance --output text |
grep '^\[HIGH\]'` filters to the high-confidence findings at a glance. Every
field comes from the already-redacted `Finding`; like every séance sink, the
text stream can never contain a raw secret.

```bash
# Default NDJSON stream (unchanged):
seance --output json | jq .

# Human-readable line stream:
seance --output text

# Only the high-confidence lines:
seance --output text | grep '^\[HIGH\]'
```

Notes:

- **Validated, not silently ignored.** An unsupported value (a typo, or `yaml`)
  fails the run at startup with a clear message rather than being quietly
  dropped. `--output sarif` is rejected with a pointer to `--sarif-file`, because
  SARIF is a *document* (written once on shutdown), not a stdout stream — see
  [SARIF report](#sarif-report---sarif-file).
- **`--output` governs only stdout.** It composes with `--output-file` (durable
  NDJSON to disk), `--sarif-file`, and `--webhook-url` unchanged — those sinks
  keep their own formats regardless of `--output`.
- **`--tui` wins on an interactive terminal.** When `--tui` takes over stdout,
  `--output` is ignored; when `--tui` falls back (non-TTY), it falls back to the
  `--output` stream you selected.

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
| `--output-max-bytes` | Rotate the `--output-file` once it would exceed this many bytes, bounding total disk for a run-forever monitor. `0` (default) appends forever. Ignored unless `--output-file` names a real file. |

Behavior and guarantees:

- **Same redacted body.** Each line is exactly the NDJSON `Finding` object shown
  in [Output format](#output-format). Because `Finding` has no raw field, the
  never-emit-raw-secrets invariant holds for the file for free — it can never
  contain a usable secret.
- **Append, never truncate.** The file is opened in append mode, so restarting
  séance extends the record instead of erasing prior findings.
- **Auto-created path.** A missing parent directory is created
  (`--output-file logs/seance.ndjson` works without a prior `mkdir`).

#### Bounded growth — size-based rotation (`--output-max-bytes`)

séance is built to run forever. Left unbounded, an append-only `--output-file`
grows until it fills the disk. `--output-max-bytes` rotates the file in place so
the on-disk record stays bounded with **no external logrotate**:

```bash
# Keep a durable NDJSON record, but never let it exceed ~100 MiB total on disk.
seance --output-file logs/seance.ndjson --output-max-bytes 26214400  # 25 MiB per file
```

When the active file would grow past the limit on the next finding, séance:

1. closes the active file and renames it to `<file>.1`,
2. shifts older generations up (`<file>.1` → `<file>.2`, …), keeping the **3 most
   recent** rotated generations and discarding anything older, and
3. opens a fresh active file and continues writing.

So total disk is bounded to roughly **4 × `--output-max-bytes`** (the active file
plus three retained generations). Notes:

- **No finding is ever split or lost.** Rotation happens *before* a line is
  written, so each finding lands wholly in one file. A single finding larger than
  the whole budget is still written intact (it just lands in a fresh file).
- **Rotation accounts for prior runs.** The threshold is measured against the
  file's real on-disk size, so a sink reopened on a near-full file rotates on its
  first write rather than overshooting.
- **`0` (default) disables rotation** — byte-for-byte the prior append-forever
  behaviour. Negative values are rejected (a typo, not a tiny file).

### Bounded run — finding cap (`--output-limit`)

séance is built to run forever, but two real workflows want the opposite — a
**bounded** run that stops after a fixed number of findings:

- a **CI gate** that fails the build the moment a secret leaks (`--output-limit 1`),
- a **research run** or **demo** that caps the firehose at, say, 100 findings
  before exit.

`--output-limit` is that cap, applied **engine-wide**:

```bash
# Stop the run after the first finding — a one-shot CI gate.
seance --output-limit 1

# Cap a research run at 100 findings, then exit cleanly.
seance --output-limit 100 --output-file research.ndjson --sarif-file research.sarif
```

| Flag | Description |
|------|-------------|
| `--output-limit` | Stop the run after this many findings have been emitted across **all** sinks. `0` (default) imposes no cap. |

Behavior and guarantees:

- **Clean shutdown, not a hard abort.** When the cap is reached séance cancels
  the run context the same way `SIGINT` does. The in-flight scan completes,
  every sink's `Close` is honoured (so the buffered SARIF document is still
  written and the webhook queue is still drained), and state — the seen-commit
  set, the seen-finding fingerprints, the ETag — is persisted to `state.json`.
  Exit status is **`0`**, like a normal SIGINT shutdown.
- **Same first-N for every sink.** The cap is applied at the engine, *before*
  the sink fan-out, so stdout/NDJSON, `--output-file`, `--sarif-file`, `--tui`,
  and the webhook all see the **identical** first `N` findings. A downstream
  consumer reading the SARIF report can never disagree with another reading the
  NDJSON stream about which findings the run kept.
- **Composes with every other filter.** It is applied **after** the confidence
  floor, the tag filter, the placeholder filter, and the suppressor — so the
  cap counts only findings that *would* have been alerts, not noise the engine
  was going to drop anyway.
- **Observable.** The stderr metrics line gains `findings_after_limit_total`,
  which counts any extra findings that arrived after the cap was reached but
  before the shutdown completed (typically a small handful from the in-flight
  scan).
- A negative value is rejected at startup (a typo, not a sub-zero cap); `0`
  imposes no cap — byte-for-byte the prior behavior.

### Global outbound rate-limit (`--rate-limit`)

séance fans GitHub API calls out across **three independent HTTP surfaces** —
the events provider, the targeted `--watch` Search-API provider, and the diff
fetcher — each with its own client and its own adaptive backoff. Those
per-surface backoffs (X-RateLimit-Remaining / X-Poll-Interval) keep each surface
inside *its own* quota, but they are mutually blind: a noisy `--watch` keyword
set polling Search-API alongside a force-push-heavy fetcher and the events
stream can collectively burst far above what a shared token (or a downstream
proxy) is willing to absorb. `--rate-limit` is the single dial that caps the
**total** outbound request rate across all three surfaces in one place.

```bash
# Hard ceiling of 5 requests/second across every séance HTTP surface combined.
seance --rate-limit 5

# Share a token with another tool: keep séance to half the budget.
seance --token "$GITHUB_TOKEN" --watch acme-corp --rate-limit 8
```

| Flag | Description |
|------|-------------|
| `--rate-limit` | Cap the **aggregate** outbound request rate, in requests per second, across the events poller, the Search-API provider, and the diff fetcher with a single shared token bucket. `0` (default) disables the cap entirely. |

Behavior and guarantees:

- **One bucket, every surface.** A single shared token-bucket limiter is
  installed on every séance HTTP client at startup. Each outbound request takes
  one token; if none is available the request blocks until one accrues, or
  until SIGINT/SIGTERM cancels the run. The fairness across the three clients
  is naturally what stdlib channel-receive scheduling provides — no one surface
  can starve the others.
- **Bounded burst.** The burst size is bounded to `ceil(rate-limit)` so a quiet
  period cannot amortise into an unbounded spike. `--rate-limit 5` means *up to
  5 requests in any one-second window after quiescence*, not "unbounded burst
  followed by 5/s".
- **Cancellable.** A request blocked waiting for a token returns immediately
  on context cancellation (SIGINT/SIGTERM), so shutdown is never delayed by a
  pending throttle wait.
- **Composes with per-surface backoff.** Each provider's existing adaptive
  backoff still runs unchanged; `--rate-limit` is a hard ceiling on top, never
  a floor. If the events poller's adaptive cadence is already inside the cap,
  the limiter is a no-op; when the cap binds, the per-surface backoffs simply
  see the throttled rate as the actual rate.
- **Inbound webhook deliveries are unaffected.** `--webhook-listen` is a
  server, not an outbound caller; its delivery latency must not depend on the
  outbound budget, so the limiter does not touch it.
- **Observable.** The stderr metrics line gains `rate_limit_throttled_total`,
  the number of outbound requests that had to wait for a token. If it stays
  at `0`, the cap is not binding — your configured rate is higher than your
  actual throughput.
- A negative value is rejected at startup (a typo, not a sub-zero rate);
  `0` (the default) disables the cap entirely — no limiter is constructed and
  the prior behaviour is preserved byte-for-byte.

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
- **GitHub code-scanning severity.** Each rule in the `tool.driver.rules[]` catalog
  carries a `helpUri`, a `defaultConfiguration.level`, the deduplicated union of its
  findings' `tags`, and a `properties["security-severity"]` numeric string
  (`"0.0"`–`"10.0"`, derived as `confidence × 10`). GitHub Advanced Security reads
  `security-severity` to bucket alerts into **Critical / High / Medium / Low** and to
  drive severity-gated branch protection — so séance findings land triaged and
  sortable instead of as undifferentiated warnings. A rule's severity reflects the
  *highest-confidence* finding that matched it, so a later low-confidence hit never
  down-rates it. Every individual `result` also carries its own
  `properties["security-severity"]`, so alerts are sortable by severity even within a
  single rule.
- **Atomic write.** The report is written via a temp file and renamed into place,
  so a crash mid-write never leaves a half-written document a SARIF consumer would
  reject. The parent directory is auto-created (`--sarif-file reports/scan.sarif`
  works without a prior `mkdir`).

### CSV export (`--csv-file`)

NDJSON and SARIF are ideal for `jq`, log stores, and security platforms — but
the moment a triager wants to open the findings in a spreadsheet, share them
with a non-security stakeholder, or bulk-import them into a ticketing system
(Jira, ServiceNow, Excel, Google Sheets), CSV is the lingua franca. Pass
`--csv-file` to *also* write a CSV export of every finding the run observed:

```bash
# Stream NDJSON to stdout as usual AND write a CSV table on shutdown.
seance --csv-file findings.csv

# Compose with every other sink at once: live feed, durable NDJSON, SARIF
# for security platforms, AND a spreadsheet-ready CSV for the bug bounty
# triage tracker.
seance \
  --tui \
  --output-file findings.ndjson \
  --sarif-file reports/scan.sarif \
  --csv-file reports/scan.csv
```

| Flag | Description |
|------|-------------|
| `--csv-file` | Write a CSV export (one header row + one row per redacted Finding) to this file in addition to whatever else is configured. The parent directory is created if missing. Empty (default) disables the CSV sink. |

The columns, in order, are: `timestamp, rule_id, rule_description, provider,
repo_owner, repo_name, commit_sha, file_path, line_number, redacted,
confidence, tags, fingerprint`. Header names match the NDJSON field names so
the two outputs are trivially correlated. Tags are joined with `;` (a CSV
cell cannot itself be a list); the timestamp is rendered as RFC 3339 UTC so
every spreadsheet/SIEM importer parses it the same way.

Behavior and guarantees:

- **One document, written on shutdown.** Unlike the streaming NDJSON sinks,
  CSV is a single header + body table, so it is buffered in memory and
  written once when séance stops (Ctrl-C / SIGTERM / `--output-limit` cap
  reached). A clean (zero-finding) run still writes a valid header-only file
  so a downstream pipeline can rely on the file existing with the documented
  schema.
- **Same redacted body.** Every column is sourced from the already-redacted
  `Finding` — because `Finding` has no raw field, the never-emit-raw-secrets
  invariant holds for the CSV export for free. The `redacted` and
  `fingerprint` columns are the privacy-preserving identifiers a triager
  uses to copy a fingerprint into `--suppress-file` and to confirm which
  key to rotate without revealing usable material.
- **RFC 4180 compliant.** The encoding/csv writer handles quoting, embedded
  commas/quotes/newlines, and CRLF line endings, so a rule description or
  file path containing any of those characters round-trips through any
  conforming CSV reader.
- **Atomic write.** The file is written via a temp file and renamed into
  place, so a crash mid-write never leaves a half-written CSV a spreadsheet
  importer would silently truncate. The parent directory is auto-created
  (`--csv-file reports/scan.csv` works without a prior `mkdir`).
- **Composes with every other sink.** It fans out from the same scan engine
  alongside stdout, `--output-file`, `--sarif-file`, `--tui`, and the
  webhook — pick any combination. With `--csv-file` unset the CSV sink is
  absent entirely and the existing data path is byte-for-byte unchanged.

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

### Syslog alerting (`--syslog-sink`)

Webhooks reach Slack and Discord; **syslog** reaches the rest of the SIEM world.
Every serious log aggregator — rsyslog, syslog-ng, journald, Splunk, ELK,
Datadog, Sumo Logic, Graylog — speaks RFC3164/RFC5424 syslog natively, usually
on UDP/TCP port 514 or a unix socket. `--syslog-sink` ships each redacted
finding as a JSON message to that pipeline directly, with no relay process and
no HTTP listener to operate.

```bash
# Local syslog — pick it up with journald, rsyslog, or whatever the host runs.
seance --syslog-sink

# A remote collector on a dedicated facility, severity derived from confidence.
seance \
  --syslog-sink \
  --syslog-network udp \
  --syslog-addr logs.example.com:514 \
  --syslog-facility local3 \
  --syslog-min-confidence 0.85
```

| Flag | Description |
|------|-------------|
| `--syslog-sink` | Enable the syslog sink. With `--syslog-network` and `--syslog-addr` both empty (the default) séance dials the local syslog socket (`/dev/log` on Linux, `/var/run/syslog` on macOS). Unsupported on Windows/Plan 9 — séance refuses to start with this flag on those platforms rather than silently dropping output. |
| `--syslog-network` | Transport for a remote collector: `udp`, `tcp`, `unixgram`, or `unix`. Empty (default) means local socket; non-empty requires `--syslog-addr` to be set too. |
| `--syslog-addr` | Address of the collector (e.g. `logs.example.com:514`) or path to a unix-domain socket. Empty uses the local socket; paired with `--syslog-network`. |
| `--syslog-tag` | Syslog tag / program name (the RFC3164 header field). Defaults to `seance`. |
| `--syslog-facility` | Facility for every message: `user` (default), `daemon`, `auth`, `authpriv`, or `local0`–`local7` (case-insensitive). Security teams typically route séance to a dedicated `localN` channel so findings are easy to forward onward without crossing other user-facility traffic. |
| `--syslog-severity` | Pin every message to a fixed severity (`emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`, case-insensitive). Empty (default) derives severity from the finding's confidence so SIEM rules can fire on header severity alone — no JSON parsing required. |
| `--syslog-min-confidence` | Per-sink confidence floor (0.0–1.0). Only findings at or above this score are shipped to syslog; complements `--min-confidence` (which applies to *all* sinks). |

**Confidence → severity mapping.** With `--syslog-severity` unset, séance maps
each finding's confidence score to a syslog severity so a SIEM rule keyed off
header severity alone can fire on high-signal findings without parsing the JSON
body. The mapping is fixed:

| Confidence | Syslog severity |
|------------|-----------------|
| ≥ 0.95 | `alert` |
| ≥ 0.85 | `crit` |
| ≥ 0.70 | `err` |
| ≥ 0.50 | `warning` |
| ≥ 0.30 | `notice` |
| < 0.30 | `info` |

Set `--syslog-severity` to override and pin every message to the same level
(e.g. `--syslog-severity warning` for a uniform-severity stream).

Behavior and guarantees:

- **Same body, fully redacted.** Each message body is exactly the NDJSON
  `Finding` object the stdout sink emits. Because `Finding` has no raw field,
  the never-emit-raw-secrets invariant holds for syslog for free — the same
  redacted record reaches every sink.
- **Lazy dial, transparent reconnect.** The syslog connection is opened on the
  first finding (so a collector that is briefly down at startup does not delay
  or fail the scan) and re-opened transparently after a transient write error
  (so a momentarily-restarting collector does not silently swallow the rest of
  the run).
- **Non-blocking.** Findings are handed to a bounded in-memory queue drained
  by a background worker. A slow or hung collector cannot apply backpressure
  to the scanner; overflow findings are dropped and counted rather than
  stalling the pipeline.
- **Fail open.** Dial or write errors are logged to stderr and the run
  continues — a dead syslog channel never takes down the monitor.
- **Startup validation.** Unknown facility/severity names, an out-of-range
  `--syslog-min-confidence`, and a half-specified network/address pair are
  rejected at startup rather than silently producing the wrong behaviour
  mid-run.

### Splunk HEC alerting (`--splunk-hec-url`)

Syslog reaches one half of the SIEM world; **Splunk HTTP Event Collector** is
how the Splunk-centric half wants to receive structured events. When
`--splunk-hec-url` is set, séance ships each redacted Finding to a Splunk HEC
endpoint as a JSON HEC envelope in addition to the stdout NDJSON stream — no
syslog input, no Universal Forwarder, no relay. The body wraps the same
redacted `Finding` the webhook sink ships, under HEC's `event` field, with
`source`, `sourcetype`, `index`, and `host` set from flags so a Splunk admin
can target it with a `props.conf` entry for field extraction out of the box.

```bash
# Minimum: URL + token. Hits the HEC endpoint as TLS by default; the token's
# default index is used.
seance \
  --splunk-hec-url https://splunk.example.com:8088/services/collector/event \
  --splunk-hec-token $SPLUNK_HEC_TOKEN

# Full: pin to an index, override source/sourcetype, skip TLS verify for an
# enterprise HEC behind a self-signed cert, and only ship high-confidence
# findings to keep the Splunk index focused.
seance \
  --splunk-hec-url https://splunk.example.com:8088/services/collector/event \
  --splunk-hec-token $SPLUNK_HEC_TOKEN \
  --splunk-hec-index seance \
  --splunk-hec-source seance-prod \
  --splunk-hec-sourcetype seance:finding \
  --splunk-hec-host alfred \
  --splunk-hec-insecure \
  --splunk-hec-min-confidence 0.85
```

| Flag | What it does |
|------|--------------|
| `--splunk-hec-url` | Full HEC endpoint, typically `https://<host>:8088/services/collector/event`. Empty (default) disables the sink. |
| `--splunk-hec-token` | HEC token, sent as `Authorization: Splunk <token>`. Required when `--splunk-hec-url` is set. The `SEANCE_SPLUNK_HEC_TOKEN` environment variable is the Docker-friendly fallback. |
| `--splunk-hec-index` | Pin every event to a specific Splunk index. Empty (default) uses the HEC token's default index. |
| `--splunk-hec-source` | HEC envelope `source` field. Empty uses `seance`. |
| `--splunk-hec-sourcetype` | HEC envelope `sourcetype` field. Empty uses `seance:finding`. |
| `--splunk-hec-host` | HEC envelope `host` field. Empty omits it and lets the HEC indexer pick (usually the sender's IP). |
| `--splunk-hec-min-confidence` | Per-sink confidence floor (0.0–1.0). Only findings at or above this score reach Splunk; complements `--min-confidence` (which applies to *all* sinks). |
| `--splunk-hec-insecure` | Skip TLS certificate verification. Enterprise HEC deployments routinely sit behind a self-signed or internal-CA certificate; this lets séance ship without bundling a CA. Default false. |

**HEC envelope shape.** Each POST body is a single JSON object:

```json
{
  "time": 1700000000.0,
  "host": "alfred",
  "source": "seance-prod",
  "sourcetype": "seance:finding",
  "index": "seance",
  "event": { "rule_id": "aws-access-key", "redacted": "AKIA…WXYZ", ... }
}
```

`time` is epoch seconds (float, sub-second precision) taken from the Finding's
own timestamp so events land at the moment of detection, not the moment of
delivery. `event` is the full redacted `Finding` object — identical to what the
webhook sink ships, identical to the NDJSON stream. There is no raw secret
material in the body; the never-emit-raw-secrets invariant holds on this
channel exactly as it does on every other.

**Properties.**

- **Non-blocking.** Findings hand off to a bounded in-memory queue (256 deep)
  drained by a single background worker. A slow or unreachable HEC never
  applies backpressure; overflow events are dropped and counted rather than
  stalling the pipeline.
- **Fail open.** A non-2xx response or transport error is logged to stderr and
  the run continues — a dead Splunk channel never takes down the monitor.
- **Startup validation.** Missing URL, missing token, or an out-of-range
  `--splunk-hec-min-confidence` are rejected at startup rather than silently
  producing the wrong behaviour mid-run.
- **Counters on the metrics line.** `splunk_hec_sent_total`,
  `splunk_hec_failed_total`, and `splunk_hec_dropped_total` are emitted on the
  periodic stderr metrics line so an operator can tell whether the channel is
  delivering, struggling, or saturated.

### S3 alerting (`--s3-bucket`)

SIEMs are one half of the security-telemetry world; the **data lake** is the
other. Athena, Glue, EMR, OpenSearch, Snowflake (via external tables), Databricks,
and every "log → S3 → query" pipeline knows how to ingest NDJSON sitting under
Hive-style partitions. When `--s3-bucket` is set, séance batches each redacted
Finding into NDJSON and PUTs the batch to S3 (or any S3-compatible API: MinIO,
LocalStack, Ceph RGW, Backblaze B2 with S3 compatibility, etc.) in addition to
the stdout NDJSON stream — no forwarder, no agent, no Firehose in the middle.

```bash
# Minimum: bucket + IAM credentials. Defaults to us-east-1, virtual-hosted
# AWS URLs, 500 findings or 4 MiB per object, flushed at least every 60s.
seance \
  --s3-bucket my-security-lake \
  --s3-access-key-id $AWS_ACCESS_KEY_ID \
  --s3-secret-access-key $AWS_SECRET_ACCESS_KEY

# Full: a per-deployment prefix, a non-us-east region, larger batches for
# cheaper Athena scans, and only high-confidence findings.
seance \
  --s3-bucket my-security-lake \
  --s3-region eu-west-2 \
  --s3-prefix seance/prod \
  --s3-access-key-id $AWS_ACCESS_KEY_ID \
  --s3-secret-access-key $AWS_SECRET_ACCESS_KEY \
  --s3-batch-size 2000 \
  --s3-batch-bytes 16777216 \
  --s3-flush-interval 5m \
  --s3-min-confidence 0.85

# MinIO / LocalStack / Ceph RGW: point at the local endpoint and force
# path-style addressing (S3-compatible servers rarely support virtual-hosted).
seance \
  --s3-bucket seance-dev \
  --s3-endpoint http://localhost:9000 \
  --s3-force-path-style \
  --s3-access-key-id minioadmin \
  --s3-secret-access-key minioadmin \
  --s3-insecure
```

| Flag | What it does |
|------|--------------|
| `--s3-bucket` | Destination S3 bucket. Empty (default) disables the sink. |
| `--s3-region` | AWS region (e.g. `us-east-1`, `eu-west-2`). Required for SigV4 signing. Empty defaults to `us-east-1`. |
| `--s3-prefix` | Object key prefix (e.g. `seance/prod`). A trailing slash is added if absent. Empty puts objects at the bucket root. |
| `--s3-access-key-id` | AWS access key id. Required when `--s3-bucket` is set. The `SEANCE_S3_ACCESS_KEY_ID` environment variable is the Docker-friendly fallback. |
| `--s3-secret-access-key` | AWS secret access key. Required when `--s3-bucket` is set. The `SEANCE_S3_SECRET_ACCESS_KEY` environment variable is the Docker-friendly fallback. |
| `--s3-session-token` | Optional STS session token (sent as `X-Amz-Security-Token`). Empty for long-lived IAM-user credentials. The `SEANCE_S3_SESSION_TOKEN` environment variable is the Docker-friendly fallback. |
| `--s3-endpoint` | Endpoint URL override (e.g. `https://minio.acme:9000`). Empty defaults to the public AWS endpoint for `--s3-region`. |
| `--s3-force-path-style` | Use path-style URLs (`https://endpoint/bucket/key`) instead of virtual-hosted (`https://bucket.endpoint/key`). Required for most S3-compatible servers and bucket names containing dots. Default false. |
| `--s3-min-confidence` | Per-sink confidence floor (0.0–1.0). Only findings at or above this score are shipped to S3. |
| `--s3-batch-size` | Max findings per S3 object. Bigger batches mean fewer PUTs (lower cost) and fatter files Athena/Glue can scan more efficiently. Default 500. |
| `--s3-batch-bytes` | Max NDJSON body size per S3 object in bytes. Reaching this caps the object before `--s3-batch-size` does. Default 4 MiB. |
| `--s3-flush-interval` | Max wall-clock time a finding may sit in the buffer before being flushed (e.g. `60s`, `5m`). Bounds how stale the freshest object can be on a low-throughput run. Default 60s. |
| `--s3-insecure` | Skip TLS verification on the endpoint. Common for MinIO/LocalStack with self-signed certs. Default false. |

**Object layout.** Every PUT lands under a Hive-style partition the major data-lake
query engines understand:

```
s3://<bucket>/<prefix>/YYYY/MM/DD/HH/seance-<unixnano>-<rand>.ndjson
```

Each object is **NDJSON** — one redacted `Finding` per line, identical to the
stdout stream. The `.ndjson` extension lets Athena auto-detect the format; the
date partitions enable partition pruning so a query for "yesterday's findings"
reads four objects, not the whole bucket. There is no raw secret material in
any object; the never-emit-raw-secrets invariant holds on this channel exactly
as it does on every other.

**Why batch?** S3 PUT is priced per request. One-PUT-per-finding would generate
thousands of objects a day, explode cost, and produce a bucket that is awful to
list and query. Athena and Glue both prefer a small number of fat files over a
sea of single-event objects. So findings buffer in memory and flush as one
NDJSON object whenever `--s3-batch-size`, `--s3-batch-bytes`, or
`--s3-flush-interval` fires first — and once more on shutdown, so a short run
still ships its findings. This mirrors the canonical pattern used by Firehose,
Vector, and Fluent Bit's S3 sinks.

**Properties.**

- **Non-blocking.** Findings hand off to a bounded in-memory channel (4096
  deep) drained by a single background flusher. A slow or unreachable bucket
  never applies backpressure; overflow events are dropped and counted rather
  than stalling the pipeline.
- **Fail open.** A non-2xx response or transport error is logged to stderr and
  the batch is dropped rather than retried indefinitely — a dead S3 endpoint
  must never balloon séance's memory or take down the monitor.
- **Flush on shutdown.** Whatever sits in the buffer when séance receives
  SIGINT/SIGTERM (or hits `--output-limit`) is PUT before the process exits, so
  a short run still lands its findings in the bucket.
- **Zero AWS-SDK dependency.** SigV4 is implemented inline with the Go
  standard library — the same five-dependency `go.mod` that powers the rest of
  séance. The Docker image stays small.
- **S3-compatible.** Tested URL builders for path-style (`--s3-force-path-style`)
  and virtual-hosted addressing; combined with `--s3-endpoint` and
  `--s3-insecure` séance writes to MinIO, LocalStack, Ceph RGW, and any other
  service speaking the S3 API.
- **Counters on the metrics line.** `s3_puts_total`, `s3_puts_failed_total`,
  `s3_findings_shipped_total`, and `s3_findings_dropped_total` are emitted on
  the periodic stderr metrics line so an operator can tell whether the channel
  is delivering, struggling, or saturated.

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
| `--dedupe-window N` | Retention window in days for the cross-run finding seen-set (re-leak suppression). `0` (default) inherits `--seen-ttl-days`, so commit dedup and finding dedup share one window — byte-for-byte the prior behaviour. A non-zero value tunes finding suppression **independently** of the commit-side bound: widen it to keep a re-pushed secret quiet longer than a commit SHA stays remembered (`--dedupe-window 30`), or tighten it to re-alert quickly after a legitimate rotation (`--dedupe-window 1`). A negative value is rejected at startup. |

```bash
# Keep commit dedup tight (7d default) but suppress re-leak fingerprints for a
# month — a force-push-then-revert that re-surfaces the same secret stays quiet
# even though the original commit SHA has long since aged out of seen-commits.
seance --dedupe-window 30
```

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

### Tag filter (`--tag` / `--exclude-tag`)

The confidence floor narrows the firehose *by score*; the tag filter narrows it
*by credential class*. Every finding carries the `tags` of the rule that matched
it (see [Output format](#output-format)) — `aws`, `cloud`, `generic`, and so on.
`--tag` and `--exclude-tag` are the categorical complement to `--min-confidence`:
an engine-wide filter that decides which classes reach **any** sink, so
stdout/NDJSON, `--output-file`, `--sarif-file`, `--tui`, and the webhook all see
the identical filtered set.

```bash
# Only hunt cloud keys — drop every other class everywhere at once.
seance --tag aws --tag gcp

# Keep the whole firehose except the noisy generic catch-all.
seance --exclude-tag generic

# Compose with the confidence floor: a finding must clear BOTH gates to emit.
seance --tag aws --min-confidence 0.85
```

| Flag | Description |
|------|-------------|
| `--tag` | Include only findings whose rule carries this tag (repeatable, case-insensitive). When set, every finding *without* a listed tag is dropped before any sink. Defaults to empty (all classes included). |
| `--exclude-tag` | Drop findings whose rule carries this tag (repeatable, case-insensitive). Applied across every sink. Defaults to empty (nothing excluded). |

- **Matching is case-insensitive** and surrounding whitespace is trimmed, so
  `--tag AWS` matches a rule tagged `aws`.
- **`--exclude-tag` wins over `--tag`.** A tag named on both lists drops the
  finding — exclude is the stronger statement.
- The filter is applied **after** the confidence floor and **before** dedup and
  the sink fan-out, so a tag-dropped finding never consumes a dedup slot and never
  reaches output. The never-store-raw invariant holds on the drop path (nothing is
  emitted at all).
- The `findings_tag_filtered_total` metric counts how many findings the tag filter
  dropped, so the trade-off is observable alongside `findings_below_confidence_total`.

> **Filter vs. rule selection.** `--tag`/`--exclude-tag` filter *findings* by their
> class at output time; `--enable-rule`/`--disable-rule`
> ([Selecting rules](#selecting-rules---enable-rule----disable-rule)) turn whole
> rules on or off by ID before scanning. Use rule selection to control *what runs*,
> the tag filter to control *which classes surface* from what ran.

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
- Optionally, a `confidence` base if the rule is markedly higher- or
  lower-trust than the default (see [Per-rule confidence](#per-rule-confidence-confidence))

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

### Per-rule confidence (`confidence`)

Every finding carries a `confidence` score in `[0.0, 1.0]` that séance computes
from rule specificity, entropy headroom, and path weight (see [Confidence
floor](#confidence-floor---min-confidence)). The starting point for that
computation is a default base of `0.80`. A rule may override that base with an
optional `confidence` field — a per-rule dial that lets a rule author make a
high-trust rule score higher, or a noisy rule lower, **without touching engine
code**:

```toml
[[rules]]
  id          = "github-pat-fine-grained"
  description = "GitHub fine-grained PAT"
  regex       = '''github_pat_[0-9a-zA-Z_]{82}'''
  keywords    = ["github_pat_"]
  confidence  = 0.98   # structurally unambiguous prefix — trust it highly

[[rules]]
  id          = "generic-api-key"
  description = "Generic api_key assignment"
  regex       = '''api[_-]?key\s*=\s*['"][0-9a-zA-Z]{16,}['"]'''
  keywords    = ["api"]
  tags        = ["generic"]
  confidence  = 0.55   # wide net — start lower so the floor filters it sooner
```

- The override sets the **base** score; the engine's specificity bonus, entropy
  headroom, and the generic-on-non-suspicious-path penalty still apply on top,
  and the final score is clamped to `[0.0, 1.0]`.
- Omitting `confidence` (or setting it to `0`) leaves the rule on the default
  base of `0.80` — byte-for-byte the prior behavior.
- It composes with `--min-confidence`: re-basing a rule low enough pushes its
  findings under the global floor, so one TOML edit can quiet a noisy rule across
  **every** sink at once.

`confidence` is **fail-safe**, like allowlists: a value outside `[0.0, 1.0]` is
ignored at runtime (the rule falls back to the default base, so a typo never
silently disables detection), and `seance rules validate` (see
[Rule validation](#validating-a-ruleset-seance-rules-validate)) flags the out-of-range value at edit time so
the author learns the override is doing nothing.

### Selecting rules (`--enable-rule` / `--disable-rule`)

Allowlists and per-rule `confidence` tune a rule *at authoring time*, by editing
the signatures file. But the signatures file is often **shared** — the shipped
`signatures/default.toml`, a team's vendored ruleset, a community file you pull
in unchanged. When one rule in that shared file is too noisy for *your*
deployment (the `generic-api-key` catch-all is the usual suspect), you shouldn't
have to fork the file to silence it. `--enable-rule` and `--disable-rule` turn an
individual rule on or off **by ID, at deploy time, without touching the
signatures TOML** — the gitleaks `--enable-rule` / `--disable-rule` analogue.

```bash
# Drop one noisy rule from the loaded ruleset; everything else still runs.
seance --disable-rule generic-api-key

# Run ONLY the two rules you care about (everything else is dropped).
seance --enable-rule aws-access-key-id --enable-rule aws-secret-access-key

# Combine: run only the AWS rules, but drop one of them.
seance --enable-rule aws-access-key-id --enable-rule aws-secret-access-key \
       --disable-rule aws-secret-access-key
```

Semantics (matching gitleaks):

- **`--enable-rule` is an allowlist.** When you pass it (repeatable), *only* the
  listed rule IDs survive — every other loaded rule is dropped. Omit it (the
  default) and all loaded rules run.
- **`--disable-rule` is a denylist** (repeatable), applied *after* `--enable-rule`.
  Any listed ID is removed from whatever survived. **`--disable-rule` always wins
  over `--enable-rule`**, so an ID in both is dropped.
- Matching is **case-insensitive** on the rule ID, and surrounding whitespace is
  trimmed. An ID that matches no rule is a harmless no-op (no error).
- Both flags carry over the [config file](#configuration-file---config) as
  `enable_rules` / `disable_rules` arrays, and follow the same
  defaults < file < flags precedence as every other flag.

Selection is **re-applied on every [SIGHUP hot-reload](#hot-reload-sighup)**, so a
long-running monitor keeps honouring your enable/disable choice even after the
signatures file changes underneath it. And it is **fail-safe**: if a selection
leaves *zero* active rules — at startup it aborts with a clear error; on a
hot-reload it logs and keeps the previously active rules — so a typo'd rule ID
can never silently disable the monitor.

This composes with the authoring-time controls rather than replacing them: use
allowlists and `confidence` to shape a rule's behaviour in a file you own, and
`--enable-rule` / `--disable-rule` to select which rules from a shared file run
in *this* deployment.

| Flag | Description |
|------|-------------|
| `--enable-rule ID` | Run *only* the listed rule IDs; every other loaded rule is dropped (allowlist). Repeatable. Empty (default) runs all rules. |
| `--disable-rule ID` | Drop the listed rule IDs from the loaded ruleset (denylist). Repeatable. Applied after `--enable-rule` and always wins over it. |

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
- a `confidence` override outside `[0.0, 1.0]` (**warning** — the engine ignores
  it and uses the default base, so the author's tuning silently does nothing)

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
  evicted on a configurable rolling TTL. By default it shares `seen_ttl_days`
  with the seen-commit set, but `--dedupe-window` lets an operator tune the
  finding-suppression window independently of the commit-side bound (e.g.
  `--dedupe-window 30` keeps re-leaks suppressed for a month while commit
  dedup still expires at 7 days). This is what suppresses cross-run re-leaks
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
  findings_below_confidence_total=4 findings_tag_filtered_total=7 \
  findings_after_limit_total=0 \
  placeholders_dropped_total=11 \
  seen_commits_tracked=412 seen_findings_tracked=6 \
  rate_limit_throttled_total=0 \
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

`findings_tag_filtered_total` counts findings dropped by the `--tag`/`--exclude-tag`
categorical filter before they reached any sink (see
[Tag filter](#tag-filter---tag----exclude-tag)). It stays at `0` unless a tag
filter is set.

`findings_after_limit_total` counts findings that arrived after the
`--output-limit` cap was reached but before the shutdown completed (see
[Bounded run](#bounded-run--finding-cap---output-limit)). It stays at `0` unless
an output limit is set.

`rate_limit_throttled_total` counts outbound HTTP requests that had to wait
for a token from the shared `--rate-limit` bucket (see
[Global outbound rate-limit](#global-outbound-rate-limit---rate-limit)). It
stays at `0` unless `--rate-limit` is set; once set, a value of `0` after
warm-up means the cap is not binding (your configured rate is higher than your
actual throughput).

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
