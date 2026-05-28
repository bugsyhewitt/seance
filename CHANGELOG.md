# Changelog

All notable changes to séance are documented here.

## [Unreleased] — v0.2 in progress

### Added

**Signature hot-reload via SIGHUP** (pipeline + scan engine)
- Sending `SIGHUP` to a running séance re-reads the `--signatures` file and
  swaps the active rule set atomically — no restart, no lost ETag, no reset of
  the seen-commit dedup set or poll cadence. Built for the run-for-days
  deployment séance targets.
- `Engine.ReloadRules` swaps the rule set under an `RWMutex`; `Scan` snapshots
  the rules under a read lock, so reloads are safe concurrent with scanning.
  `Engine.RuleCount` added for observability.
- Reloads are fail-safe: a missing file, malformed TOML, or a file parsing to
  zero rules is logged to stderr and the previously active rules are preserved —
  a bad edit can never silence the monitor. A successful reload logs the new
  rule count.
- Tests: `internal/scan/engine_test.go` adds rule-swap, empty-reload, and a
  `-race` concurrent Scan/ReloadRules test; `cmd/seance/reload_test.go` covers
  swap-on-change, keep-on-parse-error, keep-on-missing-file, skip-empty, and a
  smoke load of the real default ruleset.

**Force-push / zero-commit detection** (ingestion + fetch)
- `CommitEvent` now carries `ForcePush bool` and `BeforeSHA string`. The GitHub
  provider detects the force-push (history-rewrite) shape — HEAD reset backward
  with no distinct commits, or the payload's `forced` flag — and emits a flagged
  event carrying the now-dangling `before` SHA as the scan target. Branch
  creations and deletions (zero SHA) are excluded.
- `Fetcher.FetchCompare` recovers the diff orphaned by a force-push via
  `GET /repos/{o}/{r}/compare/{head}...{before}`, scanning the commit(s) a
  developer tried to bury. Costs one extra request per force-push only.
- Prefilter passes force-push events through even when file paths are unknown.
- New `force_pushes_total` metric on the stderr metrics line.
- Gated behind `--force-push` (default on); disable with `--force-push=false`.

**Shannon entropy analysis** (scan engine)
- `shannonEntropy(s string) float64` — bits-per-character Shannon entropy
  calculation used to distinguish random credential material from repetitive
  or human-readable strings
- Entropy gate in scan engine: when `rule.Entropy > 0`, matches whose secret
  value falls below the threshold are dropped before a Finding is emitted.
  Eliminates placeholder strings, repeated characters, and dictionary words
  that satisfy a regex shape but are not real credentials.
- `entropyConfidenceBonus` — linear bonus of 0–0.15 based on how far measured
  entropy exceeds the rule threshold (saturates at 1.0 bit of headroom)

**Dynamic confidence scoring** (replacing hardcoded 0.85)
- Base confidence: 0.80 for any match surviving keyword + regex + allowlist
- High-specificity bonus (+0.10): applied when rule keywords are 4–8 chars
  (tight prefix patterns like `AKIA`, `ghp_`, `xoxb-`)
- Entropy headroom bonus (+0–0.15): as above
- Path penalty (−0.10): generic-tagged rules on non-suspicious file paths
- Score clamped to [0.0, 1.0]

**SecretGroup extraction** (scan engine)
- Engine now honours `rule.SecretGroup` to extract the correct capture group
  as the secret value for redaction and entropy analysis. Previously the full
  match was always used; this meant rules with context-prefix captures (e.g.
  `aws_secret_access_key = "..."`) were redacting and analysing the full
  `key = value` string rather than just the value.

**Entropy thresholds added to default signatures**
- `github-pat-classic`, `github-oauth-token`, `github-app-token` → 3.5
- `stripe-secret-key`, `stripe-restricted-key` → 3.5
- `google-api-key` → 3.5
- Existing: `aws-secret-access-key` (4.0), `twilio-auth-token` (3.5),
  `generic-api-key` (3.5) unchanged

**Tests**
- `internal/scan/entropy_test.go`: 10 unit tests covering edge cases and
  boundary conditions for `shannonEntropy` and `entropyConfidenceBonus`
- `internal/scan/engine_test.go`: extended with 7 new tests covering entropy
  filtering (drop low, keep high, disabled), SecretGroup extraction, and
  confidence score range invariants

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
séance uses [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-19

First tagged release. Operational and validated against the live GitHub API.

### Added

**Ingestion**
- GitHub public events API provider: polls `GET /events` at the server-supplied
  `X-Poll-Interval` (baseline 60 s), ETag conditional requests, adaptive backoff
  when `X-RateLimit-Remaining` drops below 10% of limit
- Handles both the legacy events payload format (commits + file paths in payload)
  and the current GitHub format (head/before/ref only — file paths discovered
  via `FetchAll`)
- `GITHUB_TOKEN` environment variable supported alongside `--token` flag

**Pre-filter**
- Bot-author filter: drops commits from accounts with `[bot]` suffix
- File-path filter (legacy format): drops commits with no suspicious extensions
  or path segments before any fetch request
- Post-fetch path filter (current format): `IsInteresting` applied after
  `FetchAll` when file paths are not in the event payload

**Regex scan engine**
- Keyword pre-scan per rule to avoid catastrophic-backtrack exposure
- gitleaks-compatible TOML ruleset format (18 rules in default set)
- Allow-list suppression via stop-words

**Redaction**
- Short secrets (< 24 chars): stable SHA-256 fingerprint (`sha256:XXXXXXXX`)
  — exposing first/last 4 of a 12-char secret is itself a leak
- Long secrets (≥ 24 chars): `<first4>********************<last4>`
- Raw secret material is discarded immediately; never stored anywhere

**Output**
- NDJSON sink: one JSON object per finding, written to stdout
- Findings and diagnostics strictly separated: findings → stdout, metrics and
  logs → stderr

**State persistence**
- `SeenCommits` map persisted to `{state-dir}/state.json` (atomic write)
- 7-day rolling TTL eviction to bound file size
- On restart: deduplication map reloaded, no duplicate findings emitted
- On SIGINT/SIGTERM: graceful drain, state flush, final metrics line, exit 0

**Observability**
- Cumulative counters logged every 60 s in `key=value` format:
  `push_events_total`, `prefilter_passed_total`, `prefilter_dropped_total`,
  `fetches_total`, `polls_total`, `findings_total`
- Rate fields alongside: `push_events_hr`, `prefilter_survival_pct`,
  `fetches_hr`, `polls_hr`
- `rate_limit_remaining` and `rate_limit_reset_in` on every line
- Final cumulative snapshot emitted on every shutdown path

**Docker**
- Multi-stage build (golang:1.26-alpine → scratch)
- CA certificates included in final image (required for TLS to api.github.com)
- `GITHUB_TOKEN` env var supported without needing `--token` flag

### Validation

Run against the live GitHub public events API, 2026-05-19:
- **push_events/hr**: ~1,600 (off-peak; peak unconfirmed)
- **bot-filter drop**: ~12% of push events
- **fetches/hr**: ~1,415 (29% of 5,000 req/hr ceiling)
- **findings**: 0 in first 29 polls (expected; public commits rarely contain secrets)

Full validation notes: `docs/VALIDATION-v0.1.md`

### Known Limitations

- GitHub removed the `commits` array from PushEvent payloads (discovered during
  validation). File-path prefiltering now happens post-fetch; one API call is
  issued per non-bot push event rather than per interesting commit file.
- Peak-hour budget behaviour is unconfirmed. At 3× current load, estimated
  consumption would reach ~85% of the 5,000 req/hr ceiling. Adaptive backoff
  is the safety net.
- ETag is not persisted across restarts. The first poll after restart is a full
  fetch; subsequent polls resume conditional requests. No duplicate findings result.
- Entropy scoring not implemented in v0.1 (shipped in v0.2 development, see Unreleased section above).
- Single provider (GitHub public events). GitLab and GH Archive planned.
