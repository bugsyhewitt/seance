# Changelog

All notable changes to séance are documented here.

## [Unreleased] — v0.2 in progress

### Added

**Bounded run — finding cap (`--output-limit`)** (scan engine, config, cmd)
- New `--output-limit` flag (and `output_limit` config key) caps the total
  number of findings the run emits across **all** sinks. Targets two real
  workflows the run-forever monitor never served: a **CI gate** that fails the
  build the moment a finding lands (`--output-limit 1`) and a **bounded research
  run** or demo capped at N findings.
- The cap is **engine-wide** and applied at the sink fan-out, so stdout/NDJSON,
  `--output-file`, `--sarif-file`, `--tui`, and the webhook all see the
  **identical** first-N findings. A downstream consumer reading the SARIF report
  can never disagree with another reading the NDJSON stream about which findings
  the run kept.
- **Clean shutdown.** When the cap is reached séance cancels the run context the
  same way `SIGINT` does. The in-flight scan completes, every sink's `Close` is
  honoured (the buffered SARIF document is still written, the webhook queue is
  still drained), and state — seen-commits, seen-finding fingerprints, ETag —
  is persisted to `state.json`. Exit status is `0`, like a normal shutdown.
- Composes with every other engine-wide filter: the cap counts only findings
  that would have been emitted (after the confidence floor, tag filter,
  placeholder filter, and the suppressor), so noise the engine was already going
  to drop never consumes a slot.
- New `findings_after_limit_total` metric on the stderr `key=value` line counts
  any findings that arrived after the cap was reached but before the shutdown
  completed (typically a handful from the in-flight scan).
- A negative `--output-limit` is rejected at startup (a typo, not a sub-zero
  cap); `0` (the default) imposes no cap — byte-for-byte the prior behavior.
- Follows the `defaults < file < flags` precedence like every other config field.
- Tests: `internal/scan/outputlimit_test.go` (cap enforced, callback fires
  exactly once, zero/negative disable the cap, every sink sees the identical
  first-N), `pkg/config/config_test.go` (TOML decoding), and
  `cmd/seance/config_test.go` (flag-beats-file precedence). README documents the
  flag, examples, the shutdown guarantee, the metric, and the config-file key.

**Categorical tag output filter (`--tag` / `--exclude-tag`)** (scan engine, config, cmd)
- New `--tag` and `--exclude-tag` flags (and `include_tags` / `exclude_tags` config
  keys) filter findings by their rule's **credential class** — the categorical
  complement to the numeric `--min-confidence` floor. `--tag aws --tag gcp` admits
  only findings whose rule carries one of the listed tags; `--exclude-tag generic`
  drops a noisy class. Both are repeatable and case-insensitive.
- The filter is **engine-wide**: it drops findings before the dedup/sink fan-out, so
  every sink (stdout/NDJSON, `--output-file`, `--sarif-file`, `--tui`, the webhook)
  surfaces the identical filtered set. A tag-dropped finding never consumes a dedup
  slot and never reaches output — the never-store-raw invariant holds on the drop
  path (nothing is emitted at all).
- Precedence: `--exclude-tag` **wins over** `--tag` when a tag appears on both lists.
  Matching trims whitespace and is case-insensitive (`--tag AWS` matches `aws`). Both
  lists empty (the default) impose no filtering — byte-for-byte the prior behavior.
- Applied **after** `--min-confidence` and **before** dedup, so the two gates compose:
  a finding must clear both the confidence floor and the tag filter to emit. This lets
  an operator narrow a firehose to just the classes they hunt, or silence a class,
  across every sink at once without editing the ruleset.
- New `findings_tag_filtered_total` metric on the stderr `key=value` line counts
  findings the tag filter dropped, so the trade-off is observable alongside
  `findings_below_confidence_total`.
- Follows the `defaults < file < flags` precedence like every other config field.
- Tests: `internal/scan/tagfilter_test.go` (include admits/drops, exclude admits/drops,
  exclude-wins-over-include, case-insensitive, no-filter/whitespace-only no-op,
  composition with `--min-confidence`, no-raw-leak on the drop path) and
  `cmd/seance/config_test.go` (flag-beats-file precedence). README documents the flags,
  examples, precedence, the metric, and the config-file keys.

**Size-based rotation for `--output-file` (`--output-max-bytes`)** (output/file, config, cmd)
- New `--output-max-bytes` flag (and `output_max_bytes` config key) bounds the
  durable `--output-file` NDJSON record by rotating it in place — no external
  logrotate required. séance's intended deployment is a run-forever monitor,
  where the append-only output file otherwise grows until it fills the disk;
  this closes that unbounded-growth gap for the one mode séance is built for.
- When the active file would grow past the limit on the next finding, the file
  is closed and renamed to `<file>.1`, older generations shift up
  (`<file>.1` → `<file>.2`, …) keeping the **3 most recent** rotated generations,
  and a fresh active file is opened. Total disk is therefore bounded to roughly
  **4 × `--output-max-bytes`**.
- Rotation happens **before** a line is written, so a finding is never split
  across generations; a single finding larger than the whole budget is still
  written intact (it lands in a fresh file rather than triggering an infinite
  rotation loop). The threshold is measured against the file's real on-disk size
  (seeded from the existing file at open), so a sink reopened on a near-full file
  rotates on its first write instead of overshooting.
- `0` (the default) disables rotation — byte-for-byte the prior append-forever
  behaviour. A negative value is rejected at startup as a typo. The flag is
  ignored unless `--output-file` names a real file (not stdout).
- Tests: `internal/output/file/sink_test.go` adds disabled-by-default,
  rotate-at-threshold, no-split/no-loss-across-generations, bounded-retention,
  oversized-single-line, and seed-size-from-existing-file cases;
  `cmd/seance/config_test.go` asserts the new flag follows defaults < file <
  flags precedence. README documents the flag, an example, the rotation
  mechanics, and the config-file key.

**Tunable `--watch` search cadence (`--watch-interval`)** (ingestion/search, config, cmd)
- New `--watch-interval` flag (and `watch_interval_sec` config key) tunes, in
  seconds, how often the `--watch` Search-API provider sweeps the keyword list.
  The provider's built-in cadence is a conservative **90s** (chosen so a
  multi-keyword watch list stays inside the 30 req/min Search-API quota — each
  poll issues one request per keyword); this knob lets a single-keyword targeted
  investigation poll faster, or a long-running background monitor poll slower to
  conserve quota for other clients sharing the same token.
- Values below a **10-second floor** are clamped up with a one-line stderr
  warning, because polling faster would exhaust the quota almost immediately and
  trap séance in perpetual low-budget backoff. `0` (the default) keeps the 90s
  cadence — byte-for-byte the prior behaviour. The override has no effect unless
  `--watch` keywords are configured.
- Applies **only** to the search provider; the global events stream keeps its own
  `--poll-interval`. The separate low-budget backoff and two-way rate-limit
  recovery are untouched, so tuning the interval never weakens the quota
  protection. A new `Provider.SetPollInterval` method carries the clamp logic and
  returns the effective cadence, which the pipeline logs on startup.
- Tests: `internal/ingestion/search/provider_test.go` adds override-applied,
  below-floor-clamped, zero/negative-no-op, and cadence-governs-polling cases;
  `pkg/config/config_test.go` asserts the new TOML key overlays. README documents
  the flag, an example, and the config-file key.

**SARIF GitHub code-scanning severity enrichment** (output/sarif)
- The SARIF 2.1.0 report now enriches its `tool.driver.rules[]` catalog so GitHub
  Advanced Security / code scanning can triage séance's output **natively**. Each
  rule gains a `helpUri`, a `defaultConfiguration.level`, the deduplicated and
  deterministically-sorted union of its findings' `tags`, and a
  `properties["security-severity"]` numeric string.
- `security-severity` maps séance's `0–1` confidence onto GitHub's `"0.0"`–`"10.0"`
  CVSS-style axis (`confidence × 10`, clamped, two decimals). Code scanning reads
  it to bucket alerts into **Critical / High / Medium / Low** and to enforce
  severity-gated branch protection — previously every séance finding landed in the
  GitHub UI unclassified.
- A rule's catalog severity reflects the **highest-confidence** finding that matched
  it, so a later low-confidence hit can never down-rate it. Each individual `result`
  also carries its own `properties["security-severity"]`, so alerts are sortable by
  severity even within a single rule.
- Purely additive to the SARIF document; the redacted-only body and the
  never-store-raw invariant are unchanged (severity is derived from confidence, not
  from any secret material).
- Tests: `internal/output/sarif/sink_test.go` adds catalog security-severity +
  helpUri + defaultConfiguration, peak-confidence severity selection, sorted/deduped
  tag union, per-result security-severity, and `[0,10]` clamping/precision bounds
  (10 → 15 tests in the package).

**Per-rule confidence override (`confidence`)** (scan engine, ruleset)
- New optional `confidence` field on a rule (gitleaks-format TOML) sets that
  rule's **base** confidence score, overriding the engine default of `0.80`. A
  rule author can now make a structurally-unambiguous prefix rule score higher,
  or a wide-net generic rule score lower, **without touching engine code** — the
  per-rule complement to the engine-wide `--min-confidence` floor.
- The override is the *starting* score: the engine's high-specificity bonus,
  entropy-headroom bonus, and the generic-on-non-suspicious-path penalty still
  apply on top, and the final score is clamped to `[0.0, 1.0]`. Omitting the field
  (or setting it to `0`) leaves the rule on the default base — byte-for-byte the
  prior behavior.
- It composes with `--min-confidence`: re-basing a rule low enough pushes its
  findings under the global floor, so one TOML edit can quiet a noisy rule across
  **every** sink at once.
- **Fail-safe**, like allowlists: a value outside `[0.0, 1.0]` is ignored at
  runtime (the rule falls back to the default base, so a typo never silently
  disables detection) and `seance rules validate` flags it as a warning at edit
  time so the author learns the override is doing nothing.
- Tests: `internal/scan/ruleconfidence_test.go` (default-unchanged, override
  raises/lowers the base, clamp-at-1.0 with the specificity bonus, out-of-range
  falls back to the default, and composition with the `--min-confidence` floor)
  and `internal/scan/ruleset/validate_test.go` (out-of-range is a warning,
  in-range and the default `0` are clean).

**TOML configuration file (`--config`)** (cmd/seance, pkg/config)
- New `--config <path>` flag loads séance's entire configuration from a single
  versioned TOML file instead of a 20-flag command line — the form an operator
  actually wants for the run-forever monitor deployment under systemd/Docker.
- Precedence is **defaults < file < flags/env**: built-in defaults are the base,
  the file overlays them, and any flag the operator *also* passes overrides the
  same field in the file. `GITHUB_TOKEN` still applies on top, so the token can
  stay out of the file.
- Every operator-facing `Config` field already carried a struct tag; this makes
  that intent real. `config.Load` seeds `Defaults()`, decodes the file over it,
  and returns the file layer. Omitted keys keep their default; an **unknown key**
  is a hard error (a misspelled `webhook_ur` should be reported, not silently
  disable the alert channel), and a missing or unparseable file fails the run
  rather than quietly running on defaults.
- The merge is a pure `mergeConfig` helper driven by cobra's set-flag list, so
  the precedence rules are unit-testable in isolation; wiring lives in a
  `PersistentPreRunE`.
- No new dependency — the file is parsed with the same `BurntSushi/toml` library
  séance already uses for signatures. With no `--config` the path is byte-for-byte
  the prior flags-only behavior. The never-store-raw invariant is untouched: the
  file holds only configuration and séance still emits only redacted findings.
- Tests: `pkg/config/config_test.go` (overlay-on-defaults, empty-file-equals-
  defaults, missing-file error, invalid-TOML error, unknown-key error, string-
  slice/headers decode) and `cmd/seance/config_test.go` (flag-beats-file,
  bool-flag override of a `true` file value, no-flags-keeps-file, an end-to-end
  cobra parse proving file values survive while a CLI flag overrides, and a
  missing-file run failing the command).

**Global confidence floor (`--min-confidence`)** (scan engine)
- New `--min-confidence` flag (`0.0`–`1.0`) sets a global confidence floor: any
  finding whose computed confidence score is below it is dropped before it reaches
  **any** sink — stdout/NDJSON, `--output-file`, `--sarif-file`, `--tui`, and the
  webhook all see the identical filtered set. It is the single dial that trades
  recall for precision across the whole tool, so a noisy firehose can be tightened
  to only the findings worth a human's attention with one flag.
- Applied in the engine **before** deduplication and the sink fan-out, so a
  sub-threshold finding never consumes a dedup slot and never produces output. The
  never-store-raw invariant holds on the drop path too — nothing is emitted at all.
- Distinct from `--webhook-min-confidence`, which gates only the webhook channel
  and is applied on top of this engine-wide floor.
- Defaults to `0` (emit everything — byte-for-byte the prior behavior). Out-of-range
  values are rejected at startup so a typo fails the run loudly. New
  `findings_below_confidence_total` metric counts findings dropped by the floor, so
  the trade-off is observable on the stderr metrics line.
- Self-contained: an engine field + `WithMinConfidence`/`BelowConfidenceCount` on
  `internal/scan`, thin flag/validation/wiring in `cmd/seance` and `pkg/config`,
  no new dependencies, no architecture change.
- Tests: `internal/scan/minconfidence_test.go` (drop-below-floor with counter,
  keep-at-or-above, zero-admits-everything, clamp of out-of-range thresholds, and
  no-raw-leak on the drop path) plus an end-to-end
  `cmd/seance/integration_test.go` case proving the floor gates a sub-threshold
  finding across both the stdout and durable file sinks at once.

**Committer-date scoping for `--watch` (`--watch-since` / `--watch-until`)** (search ingestion)
- Two optional flags scope the targeted Search-API provider (`--watch`) to a
  committer-date window: `--watch-since YYYY-MM-DD` and `--watch-until
  YYYY-MM-DD`. Either bound may be set independently; together they form an
  inclusive range. The events stream is inherently *now*, but the search corpus
  is an *index of history* — without scoping, `--watch` keeps re-surfacing the
  same ancient indexed commits. This lets an operator suppress the backlog
  (`--watch-since` last week) or scope a targeted investigation to a fixed window.
- The window is rendered into GitHub's `committer-date:` search qualifier and
  appended to the keyword query, so the **index** performs the filtering
  server-side: séance issues no extra requests and never fetches commits outside
  the window. Both-bounds → `committer-date:A..B`; since-only → `>=A`;
  until-only → `<=B`.
- Validated at startup: a non-ISO date or a `--watch-since` later than
  `--watch-until` fails the run loudly rather than silently returning an
  unscoped firehose. Leaving both unset is byte-for-byte the prior behavior
  (the search corpus is unscoped); the flags apply only to the search provider —
  the global events stream is untouched.
- Purely additive and self-contained in `internal/ingestion/search` plus thin
  flag/wiring in `cmd/seance` and `pkg/config` — no new dependencies, no
  architecture change, no effect on the never-store-raw invariant (date scoping
  is a query qualifier; output is unchanged redacted `Finding`s).
- Tests: `internal/ingestion/search/provider_test.go` (qualifier rendering for
  all three window shapes, unscoped-by-default, empty-is-no-op, single-day
  window, and validation of bad/inverted ranges) plus
  `cmd/seance/watchwindow_test.go` for the startup-log description helper.

**Global placeholder / dummy-value filter** (scan engine)
- New always-on false-positive filter in the scan engine that drops matches
  carrying an unmistakable placeholder signature — discharging the v0.2 ROADMAP
  item "False-positive tuning: test-key patterns, known-dummy values". Per-rule
  `allowlist` stopwords let a rule author silence anticipated false positives,
  but documentation samples, tutorial stand-ins, and manual masks
  (`AKIAIOSFODNN7EXAMPLE`, `your_api_key`, `ghp_000…000`,
  `AKIAAAAAAAAAAAAAAAAA`) recur across *every* credential type and are
  impractical to enumerate rule-by-rule, so they are now filtered centrally.
- A candidate value is dropped if it contains a known placeholder word
  (case-insensitive substring — `example`, `placeholder`, `changeme`,
  `your_key`/`your_api_key`, `insert_key`, `dummy_key`, `redacted`, `lorem`, …),
  a run of the same character repeated 8+ times (a manual mask), or a textbook
  sequential-hex/full-alphabet fill. The filter runs after the entropy gate and
  before emission.
- **Conservative by design:** precision is weighted far above recall — a
  suppressed real leak is the catastrophic outcome, a surviving dummy is merely
  noise the entropy gate and confidence score already temper — so a randomly
  generated credential never carries these signatures and is never dropped.
- Operates only on the in-memory candidate value; nothing raw is logged,
  persisted, or emitted (the never-store-raw invariant is untouched — a dropped
  placeholder emits *nothing* to any sink). Each drop is counted in the new
  `placeholders_dropped_total` stderr metric.
- Per-rule opt-out via the `no-placeholder-filter` tag for the rare rule that
  legitimately matches placeholder-shaped values.
- Purely additive and self-contained in `internal/scan` — no new dependencies,
  no architecture change, no flag (always on). With it active, the shipped
  default ruleset's now-redundant `EXAMPLE`/`placeholder`/`xxxx` stopwords still
  function unchanged.
- Tests: `internal/scan/placeholder_test.go` (token/mono-run/sequential
  detection, the conservative real-key-passes invariant, the mono-run threshold
  boundary, and the opt-out tag) plus engine-level tests in `engine_test.go`
  (EXAMPLE key dropped + counted, mono-run mask dropped, real key passes
  uncounted, opt-out tag bypasses the filter, and no-sink-output on drop). Engine
  and integration test fixtures that previously used the AWS documented sample
  key `AKIAIOSFODNN7EXAMPLE` as a stand-in for a *real* key were updated to a
  realistic non-placeholder key, since that value is now correctly recognised as
  a placeholder.

**Ruleset pre-flight validator (`seance rules validate`)** (cmd + ruleset)
- New `rules validate` cobra subcommand and a reusable `ruleset.Validate`
  function that surface the ruleset defects the scan engine *silently tolerates*
  at runtime. The engine is fail-safe by design — a rule whose `regex` does not
  compile, or an `allowlist` whose `regexes`/`paths` pattern does not compile, is
  silently skipped at scan time so a bad edit can never crash a run-for-days
  monitor (`engine.go` swallows every `regexp.Compile` error). The cost of that
  posture is that a typo silently disables detection with no signal; the only
  symptom is a quiet stream of zero findings the operator may not notice for
  days. This is the pre-flight counterpart that makes the defect visible at edit
  time instead.
- `ruleset.Validate(rs)` returns a sorted list of `Problem`s with severity
  `error` or `warning`. **Errors:** empty/uncompilable `regex` (silently skipped
  by the engine), uncompilable allowlist `regexes`/`paths` pattern (silently
  skipped, so the false positive it meant to suppress fires), missing or
  duplicate rule `id`, and a `secretGroup` that is negative or exceeds the
  regex's capture-group count (the engine would fall back to the full match and
  over-redact). **Warnings:** a rule with no `keywords` (its regex runs against
  every line — a performance and false-positive hazard the default set always
  avoids) and an impossible `entropy` floor `> 8.0` bits/byte (the rule can never
  fire). `stopwords` and `commits` are literal/prefix axes and are never
  compiled, so regex-special characters in them are correctly *not* flagged.
- `seance rules validate [path ...]`: with no argument it validates the
  configured `--signatures` file; each argument may be a TOML file or a directory
  (every `*.toml` within it is validated, non-recursively). CI-friendly exit
  status: **0** when there are no errors (warnings alone do not fail), **1** when
  any error is found, **2** when a file cannot be read or parsed. Drops into a
  pre-commit hook or CI step to catch a broken rule before it reaches a running
  monitor; pairs naturally with the SIGHUP hot-reload workflow (validate, then
  reload).
- Purely additive: `rules` is a new subcommand group, so the bare `seance`
  invocation still launches the scan pipeline unchanged. No new dependencies
  (stdlib `regexp` + the existing cobra/toml deps), no architecture change, and
  the never-store-raw invariant is untouched (the validator only inspects rule
  *patterns*, never any secret material).
- Tests: `internal/scan/ruleset/validate_test.go` (clean ruleset, the shipped
  default ruleset validates clean, bad/empty regex, missing/duplicate id, bad
  allowlist regex + path, literal stopwords/commits not flagged, secretGroup
  in/out of range + negative, missing-keywords + impossible-entropy warnings,
  multi-problem reporting, stable sort, `Problem.String`/`HasErrors`) plus
  `cmd/seance/rules_test.go` (clean→exit 0, errors→exit 1, warnings-only→exit 0,
  unparseable→exit 2, missing file→exit 2, directory expansion ignoring non-TOML,
  the real default ruleset validates clean through the CLI path, and path
  dedup/sort). `-race` clean.

**Honor `regexes`, `paths`, and `commits` allowlist axes** (scan engine)
- The `ruleset.AllowList` struct has carried `Regexes`, `Paths`, and `Commits`
  fields since v0.1 — declared, documented as gitleaks-compatible, and parsed
  from every signatures TOML — but the scan engine only ever checked
  `StopWords`. A rule author who wrote a `regexes`, `paths`, or `commits`
  allowlist (the standard gitleaks way to silence false positives) had it
  silently ignored, so the false positives the rule explicitly tried to suppress
  fired anyway. This was shipped-but-dead allowlist code: three of four
  documented suppression axes did nothing.
- `internal/scan/engine.go` now honors all four axes. `regexes` are tested
  against the matched value alongside `stopwords` (per-match). `paths` are tested
  against the file path and `commits` against the commit SHA as rule-scoped
  short-circuits — a matching path or commit suppresses every finding the rule
  would produce in that file. Commit matching is prefix-tolerant and
  case-insensitive, so a short SHA matches a full commit SHA the way Git accepts
  abbreviated SHAs.
- **Fail-safe:** a malformed `regexes`/`paths` pattern is skipped, never treated
  as a universal match, so a typo in an allowlist can never silently disable a
  rule. This mirrors the existing fail-safe posture of SIGHUP reloads.
- Purely additive and backward-compatible: rules that use only `stopwords` (the
  two in `signatures/default.toml`, and any existing custom ruleset) behave
  byte-for-byte as before. The never-emit-raw-secrets invariant is untouched —
  allowlisting drops findings before any sink.
- Tests: seven new cases in `internal/scan/engine_test.go` covering regex
  suppression + scoping, path suppression + scoping, commit suppression +
  scoping, and the malformed-regex fail-safe. README "Signatures" section gains
  an "Allowlists" subsection documenting all four axes.

**SARIF 2.1.0 report output (`--sarif-file`)** (output + config + pipeline)
- New `internal/output/sarif` package implementing `output.Sink`: buffers each
  redacted `Finding` and, on shutdown, writes a single SARIF 2.1.0 document
  (`runs[].results[]` plus a deduplicated `tool.driver.rules[]` catalog) ingestible
  by GitHub Advanced Security / code scanning, Azure DevOps, and SARIF viewers.
  This discharges the long-documented `OutputFormat="sarif"` / v0.3 SARIF
  direction named in `pkg/config`, `docs/ARCHITECTURE.md`, and `docs/ROADMAP.md`
  that no code path previously produced.
- SARIF is a *document* format, not a stream, so the sink accumulates on `Emit`
  and serializes once on `Close` — fitting the `output.Sink` contract exactly. A
  clean (zero-finding) run still emits a valid empty-results report.
- Wired in `cmd/seance/pipeline.go` behind a new `--sarif-file` flag bound to a new
  `config.SarifPath` field; the SARIF sink fans out from the same scan engine
  alongside stdout, so it composes with `--output-file`, `--tui`, and the webhook
  sink unchanged. With `--sarif-file` unset the path is byte-for-byte identical to
  before.
- Each result is built solely from the redacted `Finding`: the redacted value and
  stable fingerprint land in `partialFingerprints`, the repo/commit/path in the
  artifact location, and confidence in `properties` (and is bucketed onto SARIF's
  `result.level`: `≥0.8`→`error`, `≥0.5`→`warning`, else `note`). `Finding` has no
  raw field, so the never-emit-raw-secrets invariant holds for free. The report is
  written atomically (temp file + rename) so a crash mid-write never leaves a
  half-written document. The séance build version is recorded as the tool driver
  version.
- Tests: new `internal/output/sarif/sink_test.go` (document envelope, field
  mapping, rule-catalog dedup, partialFingerprints, confidence→level buckets,
  no-raw-leak, idempotent Close, parent-dir creation, empty-results validity,
  atomic no-temp-leftover) plus a `cmd/seance` integration test proving the SARIF
  sink tees alongside stdout through the real scan engine. `-race` clean. README
  updated.

**ETag persistence across restarts** (ingestion + state + pipeline)
- The GitHub events ETag is now persisted to the state file and reloaded on
  startup, closing a v0.1 known limitation ("ETag is not persisted across
  restarts. The first poll after restart is a full fetch"). The `State.ETag`
  field — declared and documented since v0.1 as enabling poll resume, but never
  read or written by any code path — is now wired end to end (the same
  shipped-but-dead-field correctness debt the roadmap weighted up for the seen
  -commit eviction, finding-dedup, and output-file items).
- The events provider gains `SeedETag` (prime the conditional cursor from
  persisted state before `Stream`) and `CurrentETag` (read the live ETag back,
  safe to call concurrently with the running poll loop). The internal ETag moved
  from a poll-loop local to a mutex-guarded field.
- `cmd/seance/pipeline.go` seeds the provider from `st.ETag` at startup and, in a
  deferred flush ordered before the state save (LIFO), writes the freshest ETag
  back to state. Result: the first poll after a restart is a cheap `If-None-Match`
  conditional request (HTTP 304 when nothing new happened) instead of a full cold
  fetch that re-pulls and re-prefilters the whole events page.
- No correctness impact if the cursor expires server-side: GitHub simply returns
  a fresh 200 page and a new ETag, and seen-commit dedup still prevents duplicate
  findings. A 304 leaves the existing ETag intact so the cursor survives quiet
  polls.
- Tests: `internal/ingestion/github/provider_test.go` adds seeded-ETag-sent-as
  -If-None-Match, CurrentETag-tracks-response, and 304-preserves-ETag cases;
  ETag round-trip through the state file is already covered by
  `internal/state/state_test.go` (`TestJSONFileStorage_RoundTrip`). `-race` clean.

**Targeted / org-scoped Search-API monitoring (`--watch`)** (ingestion + pipeline) — POST_V01 Item 7
- New `internal/ingestion/search` provider implementing `ingestion.Provider`:
  polls GitHub's commit Search API (`GET /search/commits`) for operator-supplied
  `--watch` keywords (repeatable, e.g. `--watch acme-corp`). A complementary
  coverage axis to the global events firehose — it catches leaks sitting in the
  indexed corpus (repos pushed before séance started, forks, commits that
  scrolled off the events window) that the firehose never sees.
- Governs its own cadence against the Search API's separate, much stricter quota
  (30 req/min authenticated; 10/min unauthenticated): conservative ~90s sweeps
  with two-way adaptive backoff/recovery, fully independent of the events poller's
  core-API budget.
- Emitted `CommitEvent`s (`provider: "search"`, `FilesKnown=false`) fan into the
  same downstream pipeline via a new `mergeProviders` channel-merge in
  `cmd/seance/pipeline.go`; prefilter, fetch, scan, dedup, redaction, and every
  sink (NDJSON / TUI / webhook) are reused unchanged. Multi-provider support is
  purely additive at the ingestion edge.
- New metrics on the stderr line: `search_requests_total`,
  `search_results_total`, `search_commits_total`, `search_rate_limit_remaining`.
- Off by default: with no `--watch` keywords the search provider is absent
  entirely and the events-only path is byte-for-byte unchanged. Intra-run dedup
  prevents the stable Search top-results from spamming the channel between polls;
  cross-run dedup remains the pipeline's job.
- Fixture-based tests (`testdata/search_commits.json`), zero live calls in CI.
  The `mergeProviders` channel-merge is race-tested.
- New flag: `--watch` (repeatable).

**Live terminal feed (`--tui`)** (output + pipeline) — POST_V01 Item 6
- New `internal/output/tui` package implementing `output.Sink`: a scrolling,
  confidence-colored wall of recent findings above running counters (total
  findings, distinct rules hit, peak confidence). Enabled with `--tui`, it makes
  the public-events firehose watchable at a glance instead of a stream of raw
  NDJSON. The third `Sink` implementation, fanning out from the same `Scan`.
- Purely a presentation change to the primary stdout sink — coverage, dedup, and
  webhook alerting are unaffected; the same `Finding` flows the same data path.
- Graceful degradation off a TTY: when stdout is a pipe, file, or CI (`IsTTY`
  false), `--tui` is silently ignored and séance writes plain NDJSON, so a
  downstream `jq`/log store is never corrupted by escape sequences. A notice
  goes to stderr.
- Dependency-light: a small hand-rolled ANSI renderer over the stdlib, not a TUI
  framework (honors the anti-abstraction gate). No new dependencies.
- The TUI renders only the already-redacted `Finding`; the never-emit-raw-secrets
  invariant holds for free.
- New flag: `--tui`.
- Tests: `internal/output/tui/sink_test.go` covers the non-TTY plain-line path
  (no escape sequences), the TTY colored-frame render, ring bounding, confidence
  color thresholds, rune-safe truncation, `IsTTY` detection, concurrent-emit
  safety (`-race` clean), and the `output.Sink` interface conformance.

**Pluggable webhook alerting sink** (output + pipeline)
- New `internal/output/webhook` package implementing `output.Sink`: POSTs each
  finding as JSON to a configured URL with optional headers, so findings reach a
  human channel (relay, SIEM, chat bridge) in real time — séance is no longer a
  pipe you have to babysit. The second `Sink` implementation, fanning out from
  the same `Scan` as the existing stdout NDJSON sink.
- Non-blocking by construction: findings are handed to a bounded in-memory queue
  drained by a background worker, so a slow or dead endpoint never applies
  backpressure to the scanner. On overflow, findings are dropped and counted.
- Fail-open: a non-2xx response or transport error is logged to stderr and the
  run continues; a dead alerting channel never takes down the monitor.
- The POST body is the already-redacted `Finding` — the never-emit-raw-secrets
  invariant holds for the webhook for free (`Finding` has no raw field).
- New flags: `--webhook-url`, `--webhook-header KEY:VALUE` (repeatable),
  `--webhook-min-confidence` (gates alerting against the R1 confidence score).
- New metrics on the stderr line: `alerts_sent_total`, `alerts_failed_total`,
  `alerts_dropped_total`.
- Tests: `internal/output/webhook/sink_test.go` uses `httptest.Server` to assert
  POST body/shape, Authorization header, min-confidence gating, no-raw-leak,
  non-blocking behavior on 5xx and on a dead endpoint, queue-overflow drop, and
  idempotent Close (`-race` clean).

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
