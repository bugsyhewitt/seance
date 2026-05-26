# séance Roadmap

## v0.1 — MVP: GitHub events + regex scan + redacted JSON

**Goal**: a working end-to-end pipeline that can be left running and will
surface real leaked credentials from the GitHub public event stream.

- [ ] GitHub provider: real polling, ETag caching, X-Poll-Interval backoff, rate-limit header handling
- [ ] State persistence: JSON file, atomic write, cold-start modes (resume / fresh)
- [ ] Pre-filter: path/extension/bot heuristics using event payload only
- [ ] Fetcher: `GET /repos/{owner}/{repo}/commits/{sha}` with binary/size skip
- [ ] Scan engine: keyword pre-scan + regex match + redaction + allow-list suppression
- [ ] Finding confidence scoring (simple heuristic)
- [ ] NDJSON output sink
- [ ] Config file support (`seance.yaml`) in addition to flags
- [ ] Observability counters: events seen, pre-filter pass rate, fetch errors, findings, req/hr
- [ ] Fake provider and fixture-based tests for CI (no live API calls in tests)
- [ ] `go test ./... -race` passing
- [ ] Docker image published to GHCR

---

## v0.2 — Quality: entropy + live feed + false-positive hardening

- [x] Shannon entropy analysis integrated into scan engine
- [x] Per-finding confidence scoring improvements (entropy headroom, path weight)
- [ ] Live CLI display: colored terminal feed with rate-limit and finding counters
- [ ] False-positive tuning: test-key patterns, known-dummy values, path allowlists
- [ ] File output sink (rolling, configurable rotation)
- [ ] Seen-commit eviction tuning and state size bounds
- [ ] Integration test with recorded GitHub API fixtures
- [ ] Benchmark: scan throughput per second

---

## v0.3 — Breadth: GitLab (if viable), webhooks, SARIF

**GitLab prerequisite**: before implementing, validate whether GitLab exposes
any public push feed that séance can poll legally and practically. Options:
- GitLab's `/events` API requires authentication and is not a global feed
- Public project webhooks require per-project registration (not scalable)
- If no viable path exists, drop GitLab from this milestone entirely rather
  than implementing a broken or deceptive abstraction

**Items (conditional on GitLab feasibility)**:
- [ ] GitLab provider (org-scoped or user-scoped, not global stream)
- [ ] Webhook output sink (HTTP POST, configurable endpoint + auth)
- [ ] SARIF 2.1 output format (ingestible by GitHub Advanced Security / other tooling)
- [ ] `--provider github,gitlab` multi-provider flag

---

## Later

- Web UI: live findings dashboard with filtering and search
- GH Archive backfill mode: download and scan hourly archives for retrospective coverage
- More providers: Gitea, Bitbucket (assess feasibility before committing)
- Deduplication across providers (same commit seen via events + GH Archive)
- Alerting integrations: Slack, PagerDuty, webhook batch
- Rule validation tooling: `seance rules validate signatures/`
- Managed hosted mode (stretch)
