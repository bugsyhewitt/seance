# séance v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the v0.1 MVP pipeline end-to-end: GitHub events polling → pre-filter → commit fetch → regex scan → redacted NDJSON output.

**Architecture:** Five-stage pipeline (ingest → pre-filter → fetch → scan → output) with a persistent state store for ETag/dedup. Each stage is independently testable via a fake provider and fixture files. No live API calls in tests.

**Tech Stack:** Go 1.26, cobra CLI, BurntSushi/toml for signatures, stdlib net/http for API calls, stdlib encoding/json for output.

---

### Task 1: State persistence (JSON file, atomic write)

**Files:**
- Create: `internal/state/jsonfile.go`
- Test: `internal/state/state_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/state/state_test.go
package state_test

import (
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/bugsyhewitt/seance/internal/state"
)

func TestJSONFileStorage_RoundTrip(t *testing.T) {
    dir := t.TempDir()
    store := state.NewJSONFileStorage(filepath.Join(dir, "state.json"))

    s, err := store.Load()
    if err != nil {
        t.Fatalf("Load empty: %v", err)
    }
    if s.SeenCommits == nil {
        t.Fatal("Load empty: SeenCommits is nil")
    }

    s.ETag = "\"abc123\""
    s.PollCursor = "evt_42"
    s.Mark("deadbeef")
    if err := store.Save(s); err != nil {
        t.Fatalf("Save: %v", err)
    }

    s2, err := store.Load()
    if err != nil {
        t.Fatalf("Load after save: %v", err)
    }
    if s2.ETag != "\"abc123\"" {
        t.Errorf("ETag: got %q want %q", s2.ETag, "\"abc123\"")
    }
    if !s2.Seen("deadbeef") {
        t.Error("Seen: deadbeef not found after reload")
    }
}

func TestState_Evict(t *testing.T) {
    s := state.New()
    s.SeenCommits["old"] = time.Now().Add(-48 * time.Hour)
    s.SeenCommits["new"] = time.Now()
    s.Evict(24 * time.Hour)
    if s.Seen("old") {
        t.Error("old commit should have been evicted")
    }
    if !s.Seen("new") {
        t.Error("new commit should not have been evicted")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/state/... -run TestJSONFile -v
```
Expected: `FAIL — NewJSONFileStorage undefined`

- [ ] **Step 3: Implement JSONFileStorage**

```go
// internal/state/jsonfile.go
package state

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
)

type JSONFileStorage struct{ path string }

func NewJSONFileStorage(path string) *JSONFileStorage {
    return &JSONFileStorage{path: path}
}

func (s *JSONFileStorage) Load() (*State, error) {
    data, err := os.ReadFile(s.path)
    if errors.Is(err, os.ErrNotExist) {
        return New(), nil
    }
    if err != nil {
        return nil, err
    }
    var st State
    if err := json.Unmarshal(data, &st); err != nil {
        return nil, err
    }
    if st.SeenCommits == nil {
        st.SeenCommits = make(map[string]time.Time)
    }
    return &st, nil
}

func (s *JSONFileStorage) Save(st *State) error {
    if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
        return err
    }
    data, err := json.MarshalIndent(st, "", "  ")
    if err != nil {
        return err
    }
    tmp := s.path + ".tmp"
    if err := os.WriteFile(tmp, data, 0600); err != nil {
        return err
    }
    return os.Rename(tmp, s.path)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/state/... -v -race
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/state/
git commit -m "feat: implement JSON file state persistence with atomic write"
```

---

### Task 2: Pre-filter tests

**Files:**
- Test: `internal/prefilter/prefilter_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/prefilter/prefilter_test.go
package prefilter_test

import (
    "testing"

    "github.com/bugsyhewitt/seance/internal/ingestion"
    "github.com/bugsyhewitt/seance/internal/prefilter"
)

func TestFilter_SkipsBotCommit(t *testing.T) {
    e := ingestion.CommitEvent{
        AuthorName: "dependabot[bot]",
        Files:      []ingestion.FileRef{{Path: "config/settings.yaml", Status: "modified"}},
    }
    d := prefilter.Filter(e)
    if d.Keep {
        t.Error("bot commit should be filtered out")
    }
}

func TestFilter_SkipsNoFiles(t *testing.T) {
    e := ingestion.CommitEvent{AuthorName: "alice"}
    d := prefilter.Filter(e)
    if d.Keep {
        t.Error("empty commit should be filtered out")
    }
}

func TestFilter_KeepsEnvFile(t *testing.T) {
    e := ingestion.CommitEvent{
        AuthorName: "alice",
        Files:      []ingestion.FileRef{{Path: ".env", Status: "added"}},
    }
    d := prefilter.Filter(e)
    if !d.Keep {
        t.Errorf("reason: %s", d.Reason)
    }
    if len(d.Files) != 1 {
        t.Errorf("expected 1 file, got %d", len(d.Files))
    }
}

func TestFilter_KeepsPemFile(t *testing.T) {
    e := ingestion.CommitEvent{
        AuthorName: "alice",
        Files:      []ingestion.FileRef{{Path: "certs/server.pem", Status: "added"}},
    }
    d := prefilter.Filter(e)
    if !d.Keep {
        t.Errorf("reason: %s", d.Reason)
    }
}

func TestFilter_SkipsLargeCommit(t *testing.T) {
    var files []ingestion.FileRef
    for i := 0; i < 60; i++ {
        files = append(files, ingestion.FileRef{Path: "src/generated/file.go", Status: "added"})
    }
    e := ingestion.CommitEvent{AuthorName: "alice", Files: files}
    d := prefilter.Filter(e)
    if d.Keep {
        t.Error("large commit should be filtered out")
    }
}
```

- [ ] **Step 2: Run tests to verify they pass (prefilter.go already exists)**

```bash
go test ./internal/prefilter/... -v -race
```
Expected: PASS (the prefilter stub is already implemented)

- [ ] **Step 3: Commit**

```bash
git add internal/prefilter/
git commit -m "test: add prefilter unit tests"
```

---

### Task 3: GitHub provider — real polling

**Files:**
- Modify: `internal/ingestion/github/provider.go`
- Create: `internal/ingestion/github/provider_test.go`
- Create: `internal/ingestion/github/testdata/events_page1.json`

- [ ] **Step 1: Create fixture file**

Save a real `GET https://api.github.com/events` response to
`internal/ingestion/github/testdata/events_page1.json` (strip any real
tokens from the payload first). This is used in tests instead of live calls.

The JSON must be an array of event objects. At minimum include one PushEvent:

```json
[
  {
    "id": "12345678901",
    "type": "PushEvent",
    "actor": {"login": "alice"},
    "repo": {"name": "alice/my-project", "url": "https://api.github.com/repos/alice/my-project"},
    "payload": {
      "commits": [
        {
          "sha": "abc123def456abc123def456abc123def456abc1",
          "message": "update config",
          "author": {"name": "Alice", "email": "alice@example.com"},
          "added": [".env"],
          "modified": [],
          "removed": []
        }
      ]
    },
    "created_at": "2026-05-17T14:00:00Z"
  },
  {
    "id": "12345678902",
    "type": "WatchEvent",
    "actor": {"login": "bob"},
    "repo": {"name": "bob/repo"}
  }
]
```

- [ ] **Step 2: Write the failing test**

```go
// internal/ingestion/github/provider_test.go
package github_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
    "time"

    ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
)

func TestProvider_ParsesPushEvents(t *testing.T) {
    fixture, err := os.ReadFile("testdata/events_page1.json")
    if err != nil {
        t.Fatalf("read fixture: %v", err)
    }

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Poll-Interval", "60")
        w.Header().Set("ETag", `"etag123"`)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(200)
        w.Write(fixture)
    }))
    defer srv.Close()

    p := ghprovider.NewWithBaseURL("", srv.URL)
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    events, errs := p.Stream(ctx)
    var got []string
    for e := range events {
        got = append(got, e.CommitSHA)
    }
    if err := <-errs; err != nil && err.Error() != "context deadline exceeded" {
        t.Fatalf("unexpected error: %v", err)
    }

    if len(got) != 1 {
        t.Errorf("expected 1 commit event, got %d", len(got))
    }
    if len(got) > 0 && got[0] != "abc123def456abc123def456abc123def456abc1" {
        t.Errorf("unexpected SHA: %s", got[0])
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/ingestion/github/... -run TestProvider -v
```
Expected: FAIL — `NewWithBaseURL undefined`

- [ ] **Step 4: Implement polling**

In `internal/ingestion/github/provider.go`, replace the stub `Stream` with
real polling. Key requirements:
- Accept `baseURL` for testing
- Poll `{baseURL}/events` (default: `https://api.github.com/events`)
- Set `Authorization: Bearer {token}` if token non-empty
- Set `User-Agent: seance/0.1 (+https://github.com/bugsyhewitt/seance)`
- Honour `X-Poll-Interval` response header (update sleep duration)
- Use `If-None-Match: {ETag}` for conditional requests; skip on 304
- Parse JSON array of events, emit only `PushEvent` type
- For each PushEvent: emit one `CommitEvent` per commit in `payload.commits[]`
- Close channels and return when ctx is cancelled

```go
func NewWithBaseURL(token, baseURL string) *Provider {
    return &Provider{token: token, baseURL: baseURL, pollInterval: defaultPollInterval}
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/ingestion/... -v -race
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/ingestion/
git commit -m "feat: implement GitHub events polling with ETag and X-Poll-Interval"
```

---

### Task 4: Fetcher — commit diff retrieval

**Files:**
- Create: `internal/fetch/github.go`
- Create: `internal/fetch/fetcher_test.go`
- Create: `internal/fetch/testdata/commit_abc123.json`

- [ ] **Step 1: Create fixture**

Save a `GET https://api.github.com/repos/alice/my-project/commits/abc123def456...`
response to `internal/fetch/testdata/commit_abc123.json`. The response must
include a `files` array with at least one entry with a `patch` field containing
diff content that includes a test secret pattern.

```json
{
  "sha": "abc123def456abc123def456abc123def456abc1",
  "files": [
    {
      "filename": ".env",
      "status": "added",
      "patch": "@@ -0,0 +1,3 @@\n+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n+REGION=us-east-1"
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

```go
// internal/fetch/fetcher_test.go
package fetch_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/bugsyhewitt/seance/internal/fetch"
    "github.com/bugsyhewitt/seance/internal/ingestion"
)

func TestGitHubFetcher_ReturnsContent(t *testing.T) {
    fixture, _ := os.ReadFile("testdata/commit_abc123.json")
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write(fixture)
    }))
    defer srv.Close()

    f := fetch.NewGitHubFetcher("", srv.URL)
    event := ingestion.CommitEvent{
        RepoOwner: "alice", RepoName: "my-project",
        CommitSHA: "abc123def456abc123def456abc123def456abc1",
    }
    ref := ingestion.FileRef{Path: ".env", Status: "added"}

    fc, err := f.Fetch(context.Background(), event, ref)
    if err != nil {
        t.Fatalf("Fetch: %v", err)
    }
    if fc.Skipped {
        t.Fatalf("file should not be skipped, reason: %s", fc.SkipReason)
    }
    if len(fc.Lines) == 0 {
        t.Error("expected non-empty lines")
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/fetch/... -run TestGitHub -v
```
Expected: FAIL — `NewGitHubFetcher undefined`

- [ ] **Step 4: Implement GitHubFetcher**

```go
// internal/fetch/github.go
package fetch

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/bugsyhewitt/seance/internal/ingestion"
)

const maxPatchBytes = 1 << 20 // 1 MiB

type GitHubFetcher struct {
    token   string
    baseURL string
    client  *http.Client
}

func NewGitHubFetcher(token, baseURL string) *GitHubFetcher {
    return &GitHubFetcher{
        token:   token,
        baseURL: baseURL,
        client:  &http.Client{Timeout: 30 * time.Second},
    }
}

func (f *GitHubFetcher) Fetch(ctx context.Context, event ingestion.CommitEvent, ref ingestion.FileRef) (FileContent, error) {
    url := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
        f.baseURL, event.RepoOwner, event.RepoName, event.CommitSHA)

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    req.Header.Set("User-Agent", "seance/0.1 (+https://github.com/bugsyhewitt/seance)")
    req.Header.Set("Accept", "application/vnd.github+json")
    if f.token != "" {
        req.Header.Set("Authorization", "Bearer "+f.token)
    }

    resp, err := f.client.Do(req)
    if err != nil {
        return FileContent{Skipped: true, SkipReason: "fetch error: " + err.Error()}, nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return FileContent{Skipped: true, SkipReason: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
    }

    var payload struct {
        Files []struct {
            Filename string `json:"filename"`
            Patch    string `json:"patch"`
        } `json:"files"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
        return FileContent{Skipped: true, SkipReason: "decode error"}, nil
    }

    for _, file := range payload.Files {
        if file.Filename != ref.Path {
            continue
        }
        if len(file.Patch) == 0 {
            return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "empty patch"}, nil
        }
        if len(file.Patch) > maxPatchBytes {
            return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "patch too large"}, nil
        }
        return FileContent{
            Event:   event,
            FileRef: ref,
            Patch:   file.Patch,
            Lines:   strings.Split(file.Patch, "\n"),
        }, nil
    }
    return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "file not in commit response"}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/fetch/... -v -race
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/fetch/
git commit -m "feat: implement GitHub commit diff fetcher"
```

---

### Task 5: Scan engine — regex matching + redaction

**Files:**
- Modify: `internal/scan/engine.go`
- Create: `internal/scan/engine_test.go`
- Create: `internal/scan/redact.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scan/engine_test.go
package scan_test

import (
    "context"
    "testing"

    "github.com/bugsyhewitt/seance/internal/fetch"
    "github.com/bugsyhewitt/seance/internal/ingestion"
    "github.com/bugsyhewitt/seance/internal/output"
    "github.com/bugsyhewitt/seance/internal/scan"
    "github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

func TestEngine_FindsAWSKey(t *testing.T) {
    rules := []ruleset.Rule{
        {
            ID:          "aws-access-key-id",
            Description: "AWS Access Key ID",
            Regex:       `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
            Keywords:    []string{"AKIA"},
        },
    }

    var findings []output.Finding
    sink := &captureSink{findings: &findings}
    engine := scan.New(rules, sink)

    content := fetch.FileContent{
        Event:   ingestion.CommitEvent{RepoOwner: "alice", RepoName: "repo", CommitSHA: "abc123"},
        FileRef: ingestion.FileRef{Path: ".env", Status: "added"},
        Patch:   "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        Lines:   []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
    }

    n, err := engine.Scan(context.Background(), content)
    if err != nil {
        t.Fatalf("Scan: %v", err)
    }
    if n != 1 {
        t.Fatalf("expected 1 finding, got %d", n)
    }
    if findings[0].Redacted == "" {
        t.Error("Redacted must not be empty")
    }
    if len(findings[0].Redacted) >= 20 && !containsStars(findings[0].Redacted) {
        t.Error("Redacted value should be masked with stars")
    }
}

func TestEngine_NoFindingsOnAllowList(t *testing.T) {
    rules := []ruleset.Rule{
        {
            ID:       "aws-access-key-id",
            Regex:    `(?:AKIA)[A-Z0-9]{16}`,
            Keywords: []string{"AKIA"},
            AllowList: ruleset.AllowList{
                StopWords: []string{"AKIAIOSFODNN7EXAMPLE"},
            },
        },
    }
    var findings []output.Finding
    engine := scan.New(rules, &captureSink{findings: &findings})
    content := fetch.FileContent{
        Patch: "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        Lines: []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
    }
    n, _ := engine.Scan(context.Background(), content)
    if n != 0 {
        t.Errorf("expected 0 findings (allowlisted), got %d", n)
    }
}

type captureSink struct{ findings *[]output.Finding }
func (c *captureSink) Emit(_ context.Context, f output.Finding) error {
    *c.findings = append(*c.findings, f)
    return nil
}
func (c *captureSink) Close() error { return nil }

func containsStars(s string) bool {
    for _, c := range s {
        if c == '*' {
            return true
        }
    }
    return false
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scan/... -run TestEngine -v
```
Expected: FAIL — Scan returns 0 (stub)

- [ ] **Step 3: Implement redact helper**

```go
// internal/scan/redact.go
package scan

import "strings"

// redact returns a masked representation of a matched secret value.
// Shows the first 4 and last 4 characters; everything in between becomes stars.
// Raw secret material is discarded after this function returns.
func redact(s string) string {
    const stars = "********************"
    if len(s) <= 8 {
        return strings.Repeat("*", len(s))
    }
    return s[:4] + stars + s[len(s)-4:]
}
```

- [ ] **Step 4: Implement Engine.Scan**

In `internal/scan/engine.go`, replace the stub with real implementation:

```go
func (e *Engine) Scan(ctx context.Context, content fetch.FileContent) (int, error) {
    if content.Skipped {
        return 0, nil
    }
    total := 0
    for _, rule := range e.rules {
        if !keywordMatch(content.Patch, rule.Keywords) {
            continue
        }
        re, err := regexp.Compile(rule.Regex)
        if err != nil {
            continue
        }
        for lineNum, line := range content.Lines {
            matches := re.FindAllString(line, -1)
            for _, match := range matches {
                if isAllowListed(match, rule.AllowList) {
                    continue
                }
                finding := output.Finding{
                    RuleID:     rule.ID,
                    RuleDesc:   rule.Description,
                    Provider:   content.Event.Provider,
                    RepoOwner:  content.Event.RepoOwner,
                    RepoName:   content.Event.RepoName,
                    CommitSHA:  content.Event.CommitSHA,
                    FilePath:   content.FileRef.Path,
                    LineNumber: lineNum + 1,
                    Redacted:   redact(match),
                    Confidence: 0.85,
                    Tags:       rule.Tags,
                    Timestamp:  content.Event.Timestamp,
                }
                for _, sink := range e.sinks {
                    if err := sink.Emit(ctx, finding); err != nil {
                        return total, err
                    }
                }
                total++
            }
        }
    }
    return total, nil
}

func keywordMatch(s string, keywords []string) bool {
    if len(keywords) == 0 {
        return true
    }
    for _, kw := range keywords {
        if strings.Contains(s, kw) {
            return true
        }
    }
    return false
}

func isAllowListed(match string, al ruleset.AllowList) bool {
    for _, sw := range al.StopWords {
        if strings.Contains(match, sw) {
            return true
        }
    }
    return false
}
```

Add imports to engine.go: `"regexp"`, `"strings"`, `"time"`.
Add `time` import to ingestion.CommitEvent usage where Timestamp is zero value.

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/scan/... -v -race
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/scan/
git commit -m "feat: implement regex scan engine with redaction and allowlist"
```

---

### Task 6: Wire the pipeline in main.go

**Files:**
- Modify: `cmd/seance/main.go`
- Create: `cmd/seance/pipeline.go`

- [ ] **Step 1: Implement pipeline.go**

```go
// cmd/seance/pipeline.go
package main

import (
    "context"
    "fmt"
    "os"

    ghprovider "github.com/bugsyhewitt/seance/internal/ingestion/github"
    "github.com/bugsyhewitt/seance/internal/fetch"
    "github.com/bugsyhewitt/seance/internal/prefilter"
    "github.com/bugsyhewitt/seance/internal/scan"
    "github.com/bugsyhewitt/seance/internal/scan/ruleset"
    "github.com/bugsyhewitt/seance/internal/state"
    "github.com/bugsyhewitt/seance/internal/output/ndjson"
    "github.com/bugsyhewitt/seance/pkg/config"
    "path/filepath"
    "time"
)

func runPipeline(ctx context.Context, c config.Config) error {
    // Load signatures
    rs, err := ruleset.LoadFile(c.SignaturesPath)
    if err != nil {
        return fmt.Errorf("load signatures: %w", err)
    }
    fmt.Fprintf(os.Stderr, "loaded %d rules from %s\n", len(rs.Rules), c.SignaturesPath)

    // State
    store := state.NewJSONFileStorage(filepath.Join(c.StateDir, "state.json"))
    st, err := store.Load()
    if err != nil {
        return fmt.Errorf("load state: %w", err)
    }
    defer func() {
        st.LastUpdated = time.Now()
        _ = store.Save(st)
    }()

    // Sinks
    sink := ndjson.New(os.Stdout)
    defer sink.Close()

    // Engine
    engine := scan.New(rs.Rules, sink)

    // Provider
    provider := ghprovider.NewWithBaseURL(c.GitHubToken, "https://api.github.com")
    fetcher := fetch.NewGitHubFetcher(c.GitHubToken, "https://api.github.com")

    events, errs := provider.Stream(ctx)
    for {
        select {
        case event, ok := <-events:
            if !ok {
                return nil
            }
            if st.Seen(event.CommitSHA) {
                continue
            }
            st.Mark(event.CommitSHA)

            decision := prefilter.Filter(event)
            if !decision.Keep {
                continue
            }

            for _, ref := range decision.Files {
                fc, err := fetcher.Fetch(ctx, event, ref)
                if err != nil || fc.Skipped {
                    continue
                }
                if _, err := engine.Scan(ctx, fc); err != nil {
                    fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
                }
            }

        case err := <-errs:
            if err != nil {
                return fmt.Errorf("provider: %w", err)
            }
            return nil

        case <-ctx.Done():
            return nil
        }
    }
}
```

- [ ] **Step 2: Update runScan in main.go to call runPipeline**

In `cmd/seance/main.go`, replace the stub body of `runScan` with:
```go
return runPipeline(ctx, cfg)
```

- [ ] **Step 3: Build and run smoke test**

```bash
go build ./... && ./seance --help
```
Expected: help output with flags, no panic

- [ ] **Step 4: Commit**

```bash
git add cmd/seance/
git commit -m "feat: wire full pipeline in main.go"
```

---

### Task 7: Integration test with fake provider

**Files:**
- Create: `internal/ingestion/fake/provider.go`
- Create: `integration_test.go`

- [ ] **Step 1: Implement fake provider**

```go
// internal/ingestion/fake/provider.go
package fake

import (
    "context"

    "github.com/bugsyhewitt/seance/internal/ingestion"
)

// Provider emits a fixed set of CommitEvents for testing.
type Provider struct{ events []ingestion.CommitEvent }

func New(events ...ingestion.CommitEvent) *Provider { return &Provider{events: events} }
func (p *Provider) Name() string { return "fake" }

func (p *Provider) Stream(ctx context.Context) (<-chan ingestion.CommitEvent, <-chan error) {
    out := make(chan ingestion.CommitEvent, len(p.events))
    errs := make(chan error, 1)
    for _, e := range p.events {
        out <- e
    }
    close(out)
    close(errs)
    return out, errs
}
```

- [ ] **Step 2: Write integration test**

```go
// integration_test.go
package main_test

import (
    "context"
    "testing"

    "github.com/bugsyhewitt/seance/internal/ingestion"
    "github.com/bugsyhewitt/seance/internal/ingestion/fake"
    "github.com/bugsyhewitt/seance/internal/output"
    "github.com/bugsyhewitt/seance/internal/prefilter"
    "github.com/bugsyhewitt/seance/internal/scan"
    "github.com/bugsyhewitt/seance/internal/scan/ruleset"
    "github.com/bugsyhewitt/seance/internal/fetch"
)

func TestEndToEnd_FindsSecretInFakeEvent(t *testing.T) {
    event := ingestion.CommitEvent{
        Provider: "fake", RepoOwner: "alice", RepoName: "repo",
        CommitSHA: "deadbeef", AuthorName: "alice",
        Files: []ingestion.FileRef{{Path: ".env", Status: "added"}},
    }

    provider := fake.New(event)
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    events, _ := provider.Stream(ctx)

    rules := []ruleset.Rule{{
        ID: "aws-test", Regex: `AKIA[A-Z0-9]{16}`,
        Keywords: []string{"AKIA"},
    }}

    var findings []output.Finding
    sink := &collectSink{out: &findings}
    engine := scan.New(rules, sink)

    for e := range events {
        d := prefilter.Filter(e)
        if !d.Keep { continue }
        for _, ref := range d.Files {
            fc := fetch.FileContent{
                Event: e, FileRef: ref,
                Patch: "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                Lines: []string{"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
            }
            engine.Scan(ctx, fc)
        }
    }

    if len(findings) != 1 {
        t.Errorf("expected 1 finding, got %d", len(findings))
    }
}

type collectSink struct{ out *[]output.Finding }
func (c *collectSink) Emit(_ context.Context, f output.Finding) error {
    *c.out = append(*c.out, f); return nil
}
func (c *collectSink) Close() error { return nil }
```

- [ ] **Step 3: Run all tests**

```bash
go test ./... -v -race
```
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat: add fake provider and end-to-end integration test"
```

---

### Task 8: Final polish

**Files:**
- Modify: `README.md` — update install instructions once build passes
- Run: `make lint` — fix any golangci-lint issues
- Run: `go mod tidy` — clean up dependencies

- [ ] **Step 1: Run mod tidy and build**

```bash
go mod tidy && go build ./... && go test ./... -race
```
Expected: all pass

- [ ] **Step 2: Tag v0.1.0**

```bash
git tag v0.1.0
git push origin main --tags
```

---

*Plan complete. Use superpowers:subagent-driven-development to execute task-by-task.*
