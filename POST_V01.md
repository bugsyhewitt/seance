# seance — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 2, research lap)
**Baseline:** seance v0.1.0 + R1 (Shannon entropy + dynamic confidence) ships a working GitHub public-events poller → prefilter → diff-fetch → regex/entropy scan → redacted NDJSON pipeline with adaptive rate-limit cadence; tests green across all packages.

## Methodology

I read every Go source file, the README, CHANGELOG, ROADMAP, `go.mod`, the default ruleset, and all tests, then mapped seance's actual behavior against the 2025/2026 credential-leak monitoring landscape: TruffleHog (live verification, `--only-verified`, force-push-scanner), GitGuardian (real-time public monitoring, validity checks, webhook/SIEM alerting, HMSL), gitGraber (keyword/org-scoped Search-API monitoring + Slack/Telegram alerts), and Gitleaks 8 (stdin streaming, baseline + `.gitleaksignore` fingerprints). Items are ranked by hunter-value × inverse-complexity, with the dominant constraint being seance's defining posture — MIT-clean (no AGPL TruffleHog detectors), responsible-use, never-emit-raw-secrets — which rules some competitor features out and reshapes others. Two items below fix gaps where the README/CHANGELOG already *claim* behavior the code does not actually perform; those are weighted up because they are correctness debt, not just features.

---

## Item 1 — Wire up seen-commit eviction (Priority: CRITICAL)

### What
`internal/state.State.Evict(ttl)` exists, is tested, and is documented in the README ("7-day rolling TTL eviction to bound file size") and CHANGELOG — but `cmd/seance/pipeline.go` never calls it. The `SeenCommits` map grows unbounded for the life of the process and is persisted in full on every shutdown. A long-running seance (the intended deployment) leaks memory and writes an ever-larger `state.json`. This is shipped-but-dead code that makes a written guarantee the binary does not keep.

### How
- In `runPipeline`, call `st.Evict(time.Duration(c.SeenTTLDays) * 24 * time.Hour)` on a periodic ticker (reuse or parallel the existing 60s metrics goroutine; eviction every ~5–10 min is fine) and once more in the deferred shutdown flush before `store.Save`.
- `config.SeenTTLDays` already defaults to 7 — thread it through (it is currently never read by the pipeline).
- Add a metrics field `seen_commits_tracked` to the existing `key=value` stderr line so the bound is observable.
- Extend `internal/state/state_test.go` with a test asserting entries older than TTL are gone after an eviction pass and fresh ones survive; add a pipeline-level assertion if feasible with the fake provider.

### Effort estimate
Small — ~0.5 day. ~30 lines of wiring + tests. No new dependencies, no architecture change.

### Rationale
Highest value-to-effort ratio on the board: it closes a real unbounded-growth bug in the *one* mode seance is built for (run-forever monitoring) and makes an already-documented guarantee true. Fixing a correctness lie in the README costs almost nothing and protects every downstream deployment.

---

## Item 2 — Force-push / zero-commit detection (Priority: HIGH)

### What
TruffleHog's force-push-scanner established that **zero-commit force-push events are the single highest-signal indicator of intentional secret removal**: a developer commits a key, notices, and force-pushes history back to before the mistake. seance currently *drops these entirely* — in the new GitHub events format `parsePushEvent` only emits an event when `push.Head != ""` and ignores `push.Before`; a force-push that resets HEAD backward leaves a dangling commit between `before` and `head` that seance never fetches or scans. The leaked secret lives in exactly that dangling commit. This is the highest-value coverage gap relative to competitors.

### How
- In `internal/ingestion/github`, capture `push.Before` and the `ref`/distinct-commit signal. Detect the force-push shape (head moved backward / zero distinct commits but `before != head`).
- Emit a `CommitEvent` flagged (`ForcePush bool`) carrying the `before` SHA as the scan target.
- In `internal/fetch`, add `FetchCompare(ctx, before, head)` using `GET /repos/{o}/{r}/compare/{before}...{head}` (and/or fetch the dangling `before` commit directly) to retrieve the diff that was orphaned. Dangling commits remain retrievable by SHA on GitHub for a window — this is the documented mechanism the force-push-scanner relies on.
- Prefilter must let force-push events through even with `FilesKnown=false`.
- Add a `force_pushes_total` metric and a fixture-based test with a recorded force-push event payload.

### Effort estimate
Medium-large — ~2–3 days. New fetch path + ingestion-shape detection + fixtures. The compare-API call adds rate-limit cost, so gate it behind a `--force-push` flag (default on, documented) and count it in the budget metrics.

### Rationale
This is the marquee differentiator: it catches the leaks developers *try hardest to hide*, which are disproportionately real (someone panicked and rewrote history). No other MIT-licensed streaming tool does this in real time off the events feed. It directly extends seance's "listening to what the dead repos whisper" thesis to the commits that were deliberately buried, and it is purely additive — zero risk to the existing happy path.

---

## Item 3 — Pluggable alerting sink: webhook + structured POST (Priority: HIGH)

### What
seance emits NDJSON to stdout only. Every comparable monitor — gitGraber (Slack/Discord/Telegram), GitGuardian (webhook/SIEM/messaging) — treats *alerting* as table stakes because a monitor nobody is watching is useless. The `output.Sink` interface and variadic `scan.New(rules, sinks...)` are *already designed for multi-sink fan-out*; only one implementation exists. Add a generic webhook sink so findings reach a human channel in real time.

### How
- New `internal/output/webhook` package implementing `output.Sink`: POST each `Finding` as JSON to a configured URL with optional `Authorization` header; on non-2xx, log to stderr and continue (never block the pipeline).
- Buffer + small worker so a slow endpoint can't stall scanning; bounded queue, drop-with-counter on overflow (emit `alerts_dropped_total`).
- Wire flags: `--webhook-url`, `--webhook-header`, `--webhook-min-confidence` (only alert above a threshold — leverages the R1 confidence score directly).
- The POST body carries only the already-redacted `Finding` — the never-emit-raw-secrets invariant is preserved for free because `Finding` has no raw field.
- Tests with an `httptest.Server`: asserts POST shape, auth header, min-confidence gating, and that a 500 doesn't kill the run.

### Effort estimate
Medium — ~1.5–2 days. Self-contained package, stdlib `net/http`, no new deps. Slack/Telegram-specific formatters can be a later thin layer over this.

### Rationale
Turns seance from a pipe you have to babysit into a deployable monitor that pages you. High hunter-value (real-time disclosure is the whole point), low complexity (the sink abstraction already exists), and it composes cleanly with the R1 confidence score so operators tune signal/noise without code changes. Keeps the responsible-use posture intact because output stays redacted.

---

## Item 4 — Cross-run finding deduplication & re-leak suppression (Priority: HIGH)

### What
Gitleaks 8 ships baseline + `.gitleaksignore` fingerprints; GitGuardian groups duplicate incidents to fight alert fatigue. seance dedups *commits* (the `SeenCommits` map) but not *findings*: the same secret re-committed across forks, re-pushed, or matched by two overlapping rules produces duplicate alerts, and there is no way to silence a known false positive without editing the ruleset. At the firehose volume seance runs at, alert fatigue is the failure mode that gets a monitor turned off.

### How
- Compute a stable finding fingerprint from `(rule_id, redacted, repo_owner, repo_name, file_path)` — note `redacted` is already a SHA-256-derived stable identifier for short secrets, so identical secrets collide correctly without ever touching raw material.
- Add a bounded LRU/TTL set of seen fingerprints to `state.State` (persisted alongside `SeenCommits`, evicted by the same Item-1 machinery) so re-leaks within the window are suppressed.
- Add `--suppress-file` (a list of fingerprints to always ignore — the `.gitleaksignore` analogue) and emit each finding's fingerprint in the NDJSON so operators can copy it straight into the suppress file.
- Emit `findings_suppressed_total` metric. Tests: duplicate finding suppressed within window, distinct findings pass, suppress-file entry honored.

### Effort estimate
Medium — ~1.5 days. Mostly `state` + `scan` glue; reuses Item-1's eviction.

### Rationale
Directly attacks the documented industry pain point (alert fatigue) using primitives seance already has — the redacted fingerprint is privacy-preserving dedup for free, a genuinely elegant fit with the never-store-raw invariant. Pairs with Item 3: an alerting tool without dedup is a spam cannon. Medium effort because it leans on Item 1's eviction infrastructure.

---

## Item 5 — Opt-in, non-intrusive credential liveness check (Priority: MEDIUM)

### What
The biggest triage gap versus TruffleHog (`--only-verified`) and GitGuardian (validity status): seance cannot distinguish a live, dangerous AWS key from an expired test token or a placeholder. The README explicitly states "séance does not verify findings" as a *posture*, and TruffleHog's verifiers are AGPL-3.0 (forbidden here). So this must be built carefully: a **small, MIT-clean, strictly opt-in, least-privilege, read-only** liveness module — never on by default, loudly gated behind responsible-use language.

### How
- New `internal/verify` package, **disabled unless `--verify` is explicitly passed**, with a prominent stderr warning on activation about authorization and ToS.
- Implement only non-destructive, least-privilege identity probes for a handful of unambiguous credential types written from scratch (e.g. AWS `GetCallerIdentity`, GitHub `GET /user`, Stripe balance read) — no copied AGPL code; each probe is a tiny hand-written stdlib `net/http` call.
- Produce a tri-state `validity` field on `Finding` (`verified` / `unverified` / `unknown`), exactly mirroring the industry vocabulary, and a `--only-verified` flag that filters NDJSON/alerts to live findings.
- Verification needs the *raw* secret transiently in memory only at probe time; it must never be logged, persisted, or written to output — the redacted `Finding` is the only thing that leaves. Assert this invariant in tests (no raw value appears in any sink output).
- Tests use `httptest.Server` stand-ins for each provider; zero live calls in CI.

### Effort estimate
Large — ~3–4 days, plus a deliberate design-review gate. Each provider probe is small, but the responsible-use framing, the raw-secret-handling discipline, and the legal/ethical guardrails demand care. Start with 2–3 providers, not all.

### Rationale
Highest *triage* value of any item — separating live keys from dead noise is the single thing operators want most — but ranked MEDIUM because it sits in direct tension with seance's stated non-verification posture, carries the most ethical/legal risk, and must avoid AGPL contamination. It is worth doing precisely *because* it can be done the responsible way (opt-in, read-only, redacted-output-only) that distinguishes seance from tools that verify by default. Sequence it after the lower-risk wins.

---

## Item 6 — Live terminal feed (TUI) (Priority: MEDIUM)

### What
Already on the v0.2 roadmap and ubiquitous in the genre (shhgit's original draw was its live wall of findings). Today seance interleaves nothing on the terminal — findings go to stdout as raw NDJSON, metrics to stderr. A human running it interactively gets a firehose of JSON. A colored, throttled live feed showing recent findings, running counters, and rate-limit headroom makes the tool usable at a glance.

### How
- New `internal/output/tui` sink implementing `output.Sink` (again, the abstraction already supports this), enabled with `--tui`, mutually exclusive with raw NDJSON stdout (TUI to stdout, NDJSON redirectable to a file via a future file sink or `--output-file`).
- Render: scrolling recent findings (rule, repo, file, confidence-colored), live counters from the existing metrics, and a rate-limit gauge. Keep it dependency-light — a small ANSI renderer over the existing metrics struct, or one well-scoped TUI lib if justified under the anti-abstraction gate.
- Degrade gracefully when stdout is not a TTY (fall back to NDJSON) so pipelines are unaffected.
- Tests: sink emits without panicking to a non-TTY buffer; TTY rendering is smoke-tested.

### Effort estimate
Medium — ~2 days for a clean ANSI implementation; more if a TUI framework is adopted (weigh against Article VIII anti-abstraction).

### Rationale
Pure usability/adoption win with no risk to the data path — it's just another sink. Ranked MEDIUM (not higher) because it changes nothing about *what* seance catches; it makes what it already catches watchable. Good morale/demo value and it discharges an existing roadmap commitment, but it's behind the items that expand coverage and reduce noise.

---

## Item 7 — Search-API ingestion provider for targeted/org monitoring (Priority: MEDIUM)

> **STATUS: IMPLEMENTED** (R9). New `internal/ingestion/search` provider polls
> `GET /search/commits` for operator-supplied `--watch` keywords, governing its
> own cadence against the stricter Search-API quota (30 req/min auth) with two-way
> adaptive backoff/recovery. Emitted `CommitEvent`s (`provider: "search"`,
> `FilesKnown=false`) fan into the same downstream pipeline via a new
> `mergeProviders` channel-merge in `cmd/seance/pipeline.go`; prefilter, fetch,
> scan, dedup, and all sinks are reused unchanged. Search counters added to the
> metrics line (`search_requests_total`, `search_results_total`,
> `search_commits_total`, `search_rate_limit_remaining`). Fixture-based tests, no
> live CI calls. With no `--watch` keywords the provider is absent and the
> events-only path is byte-for-byte unchanged. README updated.

### What
gitGraber's whole model is keyword/org-scoped monitoring of GitHub's *code search* index — "watch for `acme-corp` + secret patterns" — which catches leaks the events firehose misses (indexed files, not just fresh pushes) and is how bug-bounty hunters got reports in 30 seconds. seance has exactly one ingestion provider (the global events stream). The `ingestion.Provider` interface was *explicitly designed* to support providers that "only support targeted repository scanning" (per its doc comment), so this is a sanctioned extension point, not a redesign.

### How
- New `internal/ingestion/search` provider implementing `ingestion.Provider`: polls GitHub's code/commit Search API for operator-supplied keywords (`--watch acme-corp,internal.example.com`), respecting the separate, stricter Search-API rate limits (30 req/min authenticated) with its own adaptive cadence.
- Emit `CommitEvent`s into the same downstream pipeline — prefilter, fetch, scan, sinks all reused unchanged.
- `--provider events,search` multi-provider flag (already foreshadowed in the v0.3 roadmap); providers run concurrently and fan into the existing channel-merge.
- Tests with recorded Search-API fixtures; no live calls in CI.

### Effort estimate
Medium-large — ~2.5–3 days. New provider + separate rate-limit governor + multi-provider wiring. The Search API's distinct quota and result-ranking quirks are the main complexity.

### Rationale
Adds a *complementary* coverage axis (targeted/indexed vs. firehose/fresh) that maps onto the highest-value real-world use case — monitoring your own org's perimeter, where GitGuardian notes 80% of corporate leaks actually surface in developers' personal repos. Ranked MEDIUM because it's a meaningful new subsystem with its own rate-limit risk surface, and the global events stream remains the v0.1 thesis; this broadens reach without being prerequisite to it. Slots naturally after the core hardening and alerting items.

---

## Item 8 — Durable NDJSON output file (`--output-file`) (Priority: HIGH)

> **STATUS: IMPLEMENTED** (R10). New `internal/output/file` package implementing
> `output.Sink`: appends each redacted `Finding` as NDJSON to a file, with the
> parent directory auto-created and the file opened in append mode so a restart
> extends rather than truncates the record. Wired in `cmd/seance/pipeline.go`
> behind `--output-file`, which finally reads the previously dead
> `config.OutputPath` field (declared and defaulted to `"-"` since v0.1 but never
> consumed anywhere). The file sink fans out from the same scan engine alongside
> the primary stdout sink, so it composes with `--tui` and the webhook sink
> unchanged. With `--output-file` unset or `"-"` the path is byte-for-byte
> identical to before. New unit tests in `internal/output/file` (write/round-trip,
> multi-finding, parent-dir creation, append-not-truncate, idempotent Close,
> no-raw-leak, bad-path error) plus a `cmd/seance` integration test proving the
> file sink tees alongside stdout through the real engine. README updated.

### What
seance had no way to keep a durable, machine-readable record of findings while
also using the live terminal feed. The TUI takes over stdout, so `--tui` and the
NDJSON stream were mutually exclusive — Item 6 explicitly flagged this ("TUI to
stdout, NDJSON redirectable to a file via a future file sink or `--output-file`").
On top of that, `config.OutputPath` was *shipped-but-dead*: declared, defaulted to
`"-"`, documented by its own presence, but never read by any code path — the same
correctness-debt category the roadmap weighted up for Items 1 and 4.

### How
- New `internal/output/file` sink: buffered, append-mode (`O_APPEND|O_CREATE`),
  parent dir created via `os.MkdirAll`, flush-on-`Close`, idempotent `Close`,
  mutex-guarded `Emit`. Body is the identical redacted NDJSON `Finding`.
- `--output-file` flag bound to the existing `cfg.OutputPath`; pipeline adds the
  file sink to the sink slice when the value is a real path (not `""`/`"-"`).
- Tests: sink unit coverage + a `cmd/seance` integration test that fans one
  finding through the real scan engine to both the stdout and file sinks.

### Effort estimate
Small — ~0.5 day. ~90 lines of sink + wiring + tests, no new dependencies, no
architecture change (the variadic-sink fan-out already existed).

### Rationale
Highest value-to-effort gap remaining after the gated Item 5: it discharges the
limitation Item 6 named, makes an already-half-built config field real (closing
correctness debt for almost nothing), and turns seance into a proper tee — live
feed for a human, durable NDJSON for tooling/SIEM — without touching the data
path or the never-store-raw invariant (the file only ever holds redacted
`Finding`s, exactly like every other sink).

---

## Item 9 — Elasticsearch / OpenSearch output sink (`--elasticsearch-url`)  ✅ IMPLEMENTED (R36)

> Shipped: `--elasticsearch-url` wires a new `internal/output/elasticsearch` sink
> that POSTs each redacted Finding to an Elasticsearch (or OpenSearch) cluster via
> the REST Index API (`POST /<index>/_doc`), alongside the existing stdout NDJSON
> stream. Index defaults to `seance-findings`; authentication via API key
> (`--elasticsearch-api-key`, sent as `Authorization: ApiKey <key>`, takes
> precedence) or HTTP Basic (`--elasticsearch-username` + `--elasticsearch-password`).
> `--elasticsearch-insecure` disables TLS verification for self-managed clusters.
> `--elasticsearch-min-confidence` is a per-sink confidence gate (complement to the
> global `--min-confidence`). Docker-friendly env-var fallbacks:
> `SEANCE_ELASTICSEARCH_API_KEY` and `SEANCE_ELASTICSEARCH_PASSWORD`. Same
> non-blocking, fail-open, bounded-queue design as the Splunk HEC sink: a slow or
> down cluster never stalls the scan. Config struct fields and TOML keys added; merge
> logic wired. No new Go dependencies; no schema change to the Finding format; no
> network calls in tests (httptest.Server). +14 tests in `internal/output/elasticsearch`.

### What
seance already fans findings into stdout NDJSON, file, webhook, Splunk HEC, syslog,
CSV, S3, and TUI sinks. Elasticsearch / OpenSearch is the dominant open-source SIEM
and log-aggregation backend — the native destination for any ELK or OpenSearch-centric
SOC. Adding an Elasticsearch sink turns séance into a direct ELK feed with no
Logstash relay, no Beats agent, and no custom pipeline.

### How
- New `internal/output/elasticsearch` sink implementing `output.Sink`: POST each
  redacted `Finding` as a JSON document to `<url>/<index>/_doc` using the
  Elasticsearch REST Index API. Auto-ID assignment (POST not PUT) so there are no
  ID-collision considerations.
- Bounded queue + single background worker, fail-open on non-2xx and transport
  errors — the same design as `splunkhec`.
- API key authentication (preferred) and HTTP Basic fallback. TLS-insecure option
  for self-signed/internal-CA clusters. Per-sink confidence gate.
- Config struct fields, TOML tags, flag registration, env-var fallback, merge logic,
  and pipeline wiring all follow the `splunkhec` pattern exactly.

### Effort estimate
Small — ~1 day. No new dependencies; clean, familiar pattern; thin presentation
layer over an already-proven queue design.

### Rationale
Elasticsearch is the highest-value remaining SIEM target in the output-sink lineage:
Splunk HEC covers the Splunk-centric SOC; Elasticsearch/OpenSearch covers everyone
else. The REST Index API is simpler than the S3 wire protocol (no SigV4, no
multipart) and mirrors the Splunk HEC pattern almost exactly, so the incremental
implementation effort is small. Completing the major SIEM sink set (Splunk + Elastic)
means séance is a drop-in feed for essentially any enterprise security telemetry
pipeline without a relay or agent.

---

## Item 10 — Kafka REST Proxy streaming sink (`--kafka-rest-url`)  ✅ IMPLEMENTED (R37)

> Shipped: `--kafka-rest-url` / `--kafka-rest-topic` wire a new
> `internal/output/kafkarest` sink that produces each redacted `Finding` to a
> Kafka topic via the Confluent REST Proxy v2 HTTP API (POST /topics/{topic},
> `Content-Type: application/vnd.kafka.json.v2+json`), also compatible with
> Redpanda's HTTP Proxy and any conforming REST Proxy implementation. Zero new
> Go dependencies — pure stdlib `net/http`. Authentication supports
> `--kafka-rest-api-key` (Bearer token, takes precedence; Confluent Cloud
> style) and `--kafka-rest-username` / `--kafka-rest-password` (HTTP Basic for
> on-prem). `--kafka-rest-insecure` disables TLS verification for self-managed
> deployments. `--kafka-rest-min-confidence` is the per-sink confidence gate.
> `SEANCE_KAFKA_REST_API_KEY` and `SEANCE_KAFKA_REST_PASSWORD` are the
> Docker-friendly env-var fallbacks. Same non-blocking, fail-open,
> bounded-queue design as every other séance streaming sink; three new counters
> on the metrics line: `kafka_rest_sent_total`, `kafka_rest_failed_total`,
> `kafka_rest_dropped_total`. 15 tests in `internal/output/kafkarest`. README
> updated with a full Kafka REST Proxy section.

### What

séance's streaming sink set covers all major SIEM/storage destinations
(Splunk HEC, Elasticsearch/OpenSearch, S3, syslog, webhook). Kafka is the
dominant real-time event bus in security data pipelines — it bridges séance to
KSQL stream-processing, Flink, Spark Streaming, and any SIEM that consumes
from Kafka (Elastic's Kafka input, Splunk Connect for Kafka). The roster's
`next_planned` explicitly named this as the next streaming output sink after
Elasticsearch.

### How

- New `internal/output/kafkarest` package implementing `output.Sink`: POST
  each redacted `Finding` as `{"records": [{"value": <Finding>}]}` to
  `<base>/topics/<topic>` using the Confluent REST Proxy v2 wire format.
- Bounded queue + single background worker, fail-open on non-2xx and transport
  errors — identical design to `splunkhec` and `elasticsearch`.
- Bearer API key auth (Confluent Cloud) and HTTP Basic auth (on-prem) with
  env-var Docker-friendly fallbacks.
- Config struct fields, TOML tags, flag registration, merge logic, pipeline
  wiring, and metrics counters all follow the established sink pattern.
- README updated with full Kafka REST Proxy section.

### Effort estimate

Small — ~1 day. No new dependencies; clean, familiar pattern.
