# séance v0.1 Validation Run

## Run Status: PRELIMINARY (in progress)

**Started:** 2026-05-19 21:09 UTC  
**Method:** `./bin/seance --state-dir validation-v0.1/state` (built binary, not `go run`)  
**Stream separation:** `1>seance.out 2>seance.err` (verified separate)  
**Checkpointing:** 15-minute metrics snapshots to `checkpoints.log`

---

## Critical Finding: GitHub API Format Change

**Before Phase B ran, a breaking change was discovered in the GitHub public events API.**

The `/events` endpoint no longer includes a `commits` array in PushEvent payloads.
The new payload contains only `head`, `before`, `ref`, `push_id`, `repository_id`.

**Impact:** The entire pre-filter model was predicated on having file paths from the event
payload — the "zero extra requests" property. That property no longer holds.

**Fix applied (before validation run):** séance now uses the `head` SHA to call
`FetchAll` (one `GET /repos/{owner}/{repo}/commits/{sha}` request per push event),
then applies `IsInteresting` path filtering on the returned file list. The bot-author
filter still works (actor login is still in the event payload).

This means the pipeline now runs as: **Ingest → Bot-filter → FetchAll → Path-filter → Scan**
rather than the original: **Ingest → File-path prefilter → Fetch(file) → Scan**.

---

## Preliminary Data (first 29 polls, ~29 minutes)

### Counters at poll 29

| Metric | Value |
|--------|-------|
| push_events_total | 773 |
| prefilter_passed_total | 677 (bot-only filter) |
| prefilter_dropped_total | 95 bots (12.3%) |
| fetches_total | 677 |
| polls_total | 29 |
| findings_total | 0 |

### Rates (steady state)

| Metric | Observed | Original Estimate | Status |
|--------|----------|-------------------|--------|
| push_events/hr | **1,600** | 3,000 | Lower — off-peak or estimate was high |
| bot filter drop % | **12.3%** | n/a | — |
| fetch-filter survival | **88%** | 15% (file-path filter) | Different model — see below |
| fetches/hr | **1,415** | 900 | Higher — see below |
| polls/hr | **60** | 60 | Matches |
| total req/hr | **~1,475** | 960 | Higher — see below |
| rate_limit budget used | **~29.5%** | ~19% | Higher but well within ceiling |
| findings/hr | **0** | unknown | See below |

### Rate Limit Consumption

```
5,000 - 4,285 = 715 requests consumed in 29 minutes
Annualised: ~1,479 req/hr
Budget ceiling: 5,000 req/hr
Headroom: 3,521 req/hr (70.4%)
```

Process has not hit the backoff threshold (10% = 500 remaining).

---

## Budget Reconciliation (preliminary)

### Why fetches/hr is higher than estimated

The original model assumed file-path prefiltering would drop 85% of commits before any
API call. That model is no longer valid because GitHub removed file paths from the payload.

The new model: **1 fetch per non-bot push event**. Bots account for ~12% of events, so:

```
push_events/hr:     1,600
Bot-filtered:         200 (12.5%)
Fetches issued:     1,400/hr
Polls:                 60/hr
Total req/hr:       1,460/hr (29.2% of 5,000 budget)
```

Even at 3x current load (assuming this is off-peak and peak is 3× higher):

```
push_events/hr:     4,800 (hypothetical peak)
Bot-filtered:         600 (12.5%)
Fetches:            4,200/hr
Polls:                 60/hr
Total:              4,260/hr → 85.2% of 5,000 budget
```

85% of budget at peak is uncomfortably close. The adaptive backoff (fires at <500
remaining, i.e., <10%) would engage if peak exceeds this. The 24-hour run
must confirm what peak actually looks like.

### Why fetches/hr < original estimate despite 88% survival

Original model counted commits (plural per push) at 15% survival.
New model counts push events (one HEAD commit per push) at 88% survival.
Push events/hr is **lower** than the commit count the original model assumed, so total
fetches are comparable: original 900/hr vs. observed 1,415/hr.

The new model also has a structural advantage: one FetchAll call returns all changed files
in one request, regardless of how many files changed. The old model made one request per
interesting file per commit (multiple requests for multi-file commits). The new model is
more API-efficient per byte of content retrieved.

### Findings

**0 findings in 677 commits.** This is expected and not a bug.

Spot-check of 15 commits: 1/15 (6.7%) had a file matching `IsInteresting` —
`token-efficiency.md` (false positive from the `token` keyword). The regex engine
correctly found no credentials in that markdown file.

Most public push events are code/documentation changes. Leaked secrets are rare events;
their expected occurrence rate in random public commits is extremely low. A longer run
(24 hours) is needed to see any findings, and even then findings may be zero for a
single-day window.

---

## Checkpoints Collected

```
2026-05-20T01:25:02Z  polls_total=15  push_events_hr=1595.9  prefilter_survival=89.7%  fetches_hr=1431.9  rl_remaining=4645
```

(15-minute checkpoint captures will continue accumulating in `checkpoints.log`.)

---

## What Remains for Full Validation

The run is **still active** (PID in `validation-v0.1/seance.pid`). It needs to run
through at minimum one US business-hours cycle (14:00–22:00 UTC) to capture peak push
volume. The rate_limit_reset behaviour and backoff/recovery should be confirmed over
multiple window resets.

**What to check after 24 hours:**

1. Peak push_events/hr — does it exceed 3,000?
2. Peak fetches/hr — does it approach the 5,000 ceiling?
3. Did the adaptive backoff engage? If so, at what push volume?
4. Any findings? If yes, are they correctly redacted (no raw secrets in seance.out)?
5. Does rate_limit_remaining recover after each 60-minute window reset?

---

## Stream Integrity Check

All findings go to stdout (`seance.out`). All metrics and diagnostics go to stderr
(`seance.err`). Verified: `seance.out` contains 0 bytes of non-finding content.

```
grep "séance metrics" seance.out  # must return nothing
wc -c seance.out                   # bytes = findings NDJSON only
```

---

## Redaction Integrity Check (to run post-24h)

```bash
# Any line in seance.out that is not empty and has no sha256: and no * is suspicious.
grep -v '"redacted":"sha256:' seance.out | grep -v '"redacted":"' | grep -v '^$'
# Expected: empty output
```

---

## Preliminary Conclusion

The API format change is the key finding of Phase B. The original budget model (960 req/hr)
was based on a pre-filter that no longer works because GitHub removed file paths from the
event payload. The revised model (1,475 req/hr at current load) is still comfortably
within the 5,000 req/hr ceiling.

**Decision gates for Phase C:**
- If 24h peak stays below 3,500 req/hr → budget is sound, proceed
- If 24h peak exceeds 4,000 req/hr → tighten bot/ref filtering, consider sampling
- If backoff engages → the adaptive mechanism is working; note the threshold
