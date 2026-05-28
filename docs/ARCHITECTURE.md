# séance — Architecture

## Overview

séance is a five-stage pipeline. Each stage is independent; the output of one
feeds the next. The design is optimized for three hard constraints:

1. **Rate-limit budget** — 5,000 req/hr per GitHub account, not per token
2. **False-positive rate** — noisy scanners get uninstalled
3. **Secret handling** — séance must never become a credential database

```
┌──────────────┐    CommitEvent    ┌──────────────┐  Decision(Keep=true)  ┌─────────────┐
│  1. INGEST   │ ──────────────── ▶│ 2. PRE-FILTER│ ───────────────────── ▶│  3. FETCH   │
│  (Provider)  │                   │  (no fetch)  │                         │ (Fetcher)  │
└──────────────┘                   └──────────────┘                         └─────────────┘
                                                                                    │
                                                                               FileContent
                                                                                    │
                                                                                    ▼
                                                                           ┌─────────────┐    Finding    ┌─────────────┐
                                                                           │  4. SCAN    │ ────────────── ▶│ 5. OUTPUT  │
                                                                           │  (Engine)   │               │  (Sink[])   │
                                                                           └─────────────┘               └─────────────┘
```

---

## Stage 1 — Ingestion (`internal/ingestion/`)

**Job**: emit `CommitEvent` values from a source provider.

**GitHub provider** (`internal/ingestion/github/`): polls `GET /api.github.com/events`
at the interval returned in `X-Poll-Interval` (baseline: 60s). Uses ETag
conditional requests to avoid re-processing. Emits only PushEvents, converting
each commit in the payload to a `CommitEvent`.

**Provider interface** is deliberately narrow:

```go
type Provider interface {
    Name() string
    Stream(ctx context.Context) (<-chan CommitEvent, <-chan error)
}
```

`Stream` does not imply a global public feed exists. The GitHub implementation
happens to poll the public events endpoint; a hypothetical repo-scoped provider
would poll specific repositories instead.

**GitLab caveat**: GitLab has no comparable global public push event feed.
A GitLab provider is possible for organisation-scoped scanning only.
Feasibility for v0.3 must be validated before the interface is committed.

**State interaction**: on startup the provider initialises with an empty ETag,
so the first poll always returns a full event list (HTTP 200). After the first
successful poll the ETag is cached in memory and subsequent polls within the
same process use conditional requests (HTTP 304 when nothing changed).
ETag persistence across restarts is a v0.2 optimisation — on restart, one
extra full poll occurs, after which conditional requests resume.

`SeenCommits` **are** persisted to disk. On restart the deduplication map is
reloaded and commits already processed in the previous run are skipped, so
no duplicate findings are emitted regardless of ETag state.

---

## Stage 2 — Pre-Filter (`internal/prefilter/`)

**Job**: discard commits that are unlikely to contain secrets, using **only
data already in the event payload** (zero extra API requests).

This stage exists for one reason: the naive approach of fetching every changed
file of every commit would exhaust the 5,000 req/hr rate-limit budget by 9×.
Pre-filtering reduces request consumption to ~19% of budget.

**Heuristics applied (no fetch)**:
- Skip commits with no files
- Skip commits from bot accounts (name/email suffix `[bot]`)
- Skip commits with >50 files (likely generated or mass-rename)
- Keep commits where ≥1 file matches a suspicious path pattern:
  - Extensions: `.pem`, `.key`, `.pfx`, `.p12`, `.env`, `.htpasswd`, etc.
  - Path segments: `.aws/`, `.ssh/`, `secret`, `credential`, `token`, `password`, etc.

**Pass rate**: empirically ~12–18% of commits survive. Combined with 1 request
per surviving commit (not per file), total fetch requests are ~900–1,800/hr.

---

## Stage 3 — Fetch (`internal/fetch/`)

**Job**: retrieve file content (diffs/patches) for commits that survived pre-filter.

One `GET /repos/{owner}/{repo}/commits/{sha}` request returns the full diff for
all changed files. Content for binary files, files over a size threshold, or
files with empty patches is skipped without error.

The `FileContent` type carries the raw patch and per-line split for the scan
stage.

---

## Stage 4 — Scan (`internal/scan/`)

**Job**: run the signature engine over `FileContent` and emit `Finding` values.

**Signature engine** (v0.1: regex only, v0.2: + entropy):

1. **Keyword pre-scan**: each `Rule` carries a `keywords` list. If none of the
   keywords appear in the patch (fast substring check), the regex is skipped.
   This prevents catastrophic-backtrack exposure to adversarial input.

2. **Regex match**: compiled `Rule.Regex` is applied line-by-line.

3. **Secret group extraction**: `Rule.SecretGroup` identifies the capture group
   containing the secret value. Only that group is passed to the redaction step.

4. **Redaction**: the extracted value is reduced to `<first4>****<last4>` before
   being placed in the `Finding.Redacted` field. Raw secret material is
   immediately discarded and never stored anywhere.

5. **Allow-list suppression**: matches are dropped if the path matches
   `AllowList.Paths`, the value matches `AllowList.Regexes`, or the raw value
   contains any `AllowList.StopWords` (e.g. `changeme`, `your_api_key`).

6. **Entropy scoring** (v0.2): if `Rule.Entropy > 0`, the extracted value's
   Shannon entropy is computed. Matches below the threshold are dropped.

**Confidence scoring**: a simple heuristic combining rule specificity,
entropy headroom, and path match quality. Range: 0.0–1.0.

**Ruleset format**: gitleaks-compatible TOML (MIT-licensed). Do not add
TruffleHog detectors — TruffleHog is AGPL-3.0.

---

## Stage 5 — Output / Sink (`internal/output/`)

**Job**: emit `Finding` values to one or more configured sinks.

**Sink interface**:
```go
type Sink interface {
    Emit(ctx context.Context, finding Finding) error
    Close() error
}
```

**Built-in sinks**:
- `ndjson` — newline-delimited JSON to stdout or file (v0.1)
- `file` — same as ndjson but to a rolling file (v0.2)
- `webhook` — HTTP POST per finding (v0.3)
- `sarif` — SARIF 2.1.0 report (`--sarif-file`), ingestible by GitHub Advanced Security (shipped)

---

## State Persistence (`internal/state/`)

séance is not stateless. Three pieces of state must survive restarts:

| Field | Purpose | Persisted? |
|-------|---------|-----------|
| `ETag` | Conditional GET — avoids re-fetching unchanged event pages | In-memory only (v0.1); resets on restart, one extra full poll occurs |
| `PollCursor` | Last-seen event ID | Persisted (not yet wired to GitHub provider in v0.1) |
| `SeenCommits` | Deduplication map — prevents duplicate findings | Persisted; loaded on startup, so restarts produce no duplicates |

State is persisted as JSON in `{state-dir}/state.json`, written atomically
(temp file + rename). Entries in `SeenCommits` older than `seen_ttl` (default
7 days) are evicted to bound file size.

### Restart Resume Behaviour (v0.1)

On clean shutdown (SIGINT / SIGTERM), séance:
1. Stops ingestion (context cancelled).
2. Saves state to disk via atomic write (temp file + rename).
3. Emits a final cumulative metrics line to stderr.
4. Exits 0.

On restart:
- `SeenCommits` is reloaded — commits already processed are skipped and
  produce no duplicate findings.
- The persisted ETag is reloaded and seeded into the events provider, so the
  first poll after a restart is a conditional request (`If-None-Match`). When
  nothing new happened it answers HTTP 304 (no body, no extra page to
  prefilter); when the cursor has expired server-side GitHub returns a fresh
  page and ETag. Either way there are no duplicate findings.
- Subsequent polls within the new process use conditional requests as normal.

Verified by `TestRestartDeduplication` in `internal/state/state_test.go`.

---

## Rate-Limit Strategy

```
Budget:          5,000 req/hr (hard ceiling, per GitHub account)

Polling:         3,600s/hr ÷ 60s/poll = 60 req/hr
Visible pushes:  60 polls × 50 PushEvents avg = 3,000 PushEvents/hr
Commits:         3,000 × 2 avg commits = 6,000 commits/hr
Pre-filter (15%): 6,000 × 0.15 = 900 surviving commits/hr
Fetch:           900 × 1 req/commit = 900 req/hr

Total:           60 + 900 = 960 req/hr  (19.2% of 5,000 budget)
Headroom at 30%: 60 + 1,800 = 1,860 req/hr (37.2%)
Headroom at 50%: 60 + 3,000 = 3,060 req/hr (61.2%)
```

The pre-filter is not an optimisation — it is a first-class pipeline stage
required for séance to operate within its API budget.

---

## Secret Handling Invariant

**Raw secret material is never written to disk, logs, or any output.**

This is a hard invariant, not a default, not a flag, not a configuration option.

Every `Finding` carries:
- `Redacted`: `<first4>****<last4>` of the matched value (enough to identify, not to abuse)
- Full locator metadata: provider, repo, owner, commit SHA, file path, line number

If a future version adds a `--full-secrets` flag, it must:
1. Be off by default, always
2. Emit a loud warning to stderr on every invocation
3. Be documented as the operator's sole legal responsibility
4. Write output only to a local file, never stdout

---

## Verification Stance

séance **does not verify** discovered credentials. It does not authenticate
against provider APIs to confirm a key is live.

TruffleHog-style verification is standard when scanning **your own** repositories.
séance scans **strangers' repositories**. Authenticating with a credential found
in someone else's repository, without authorization, is a materially different
legal posture — regardless of the technical capability.

If verification is ever added:
- Off by default
- Explicit `--verify` flag with a printed legal warning
- Documented as the operator's own legal responsibility

---

## Provider Interface Design Note

The `Provider` interface does not include a method like `GlobalStream()` or
`AllPublicEvents()` because that operation is not universally available across
providers. The GitHub implementation polls a public endpoint that happens to
aggregate events from the entire platform. A future GitLab implementation,
if feasible, would likely poll organisation- or project-scoped webhooks instead.

Designing for the intersection of what all providers can do, rather than the
superset of what one provider offers, keeps the interface honest.
