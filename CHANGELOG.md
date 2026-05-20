# Changelog

All notable changes to séance are documented here.
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
- Entropy scoring is not yet implemented (planned for v0.2).
- Single provider (GitHub public events). GitLab and GH Archive planned.
