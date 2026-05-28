// Package sarif implements an output.Sink that writes séance findings as a
// SARIF 2.1.0 document — the Static Analysis Results Interchange Format, an OASIS
// standard ingestible by GitHub Advanced Security ("Code scanning"), Azure DevOps,
// VS Code SARIF viewers, and most security tooling. This discharges the
// long-documented `--output sarif` / OutputFormat="sarif" direction (named in
// pkg/config, docs/ARCHITECTURE.md, and docs/ROADMAP.md as a v0.3 target) that no
// code path previously produced.
//
// SARIF is a *document* format, not a stream: a single top-level JSON object
// carries a `runs[].results[]` array plus a `tool.driver.rules[]` catalog. Unlike
// the NDJSON and file sinks (one object per line), the SARIF sink therefore
// BUFFERS each Finding on Emit and serializes the complete document once on Close.
// This fits the output.Sink contract exactly — Emit accumulates, Close finalizes.
//
// Design constraints, in priority order:
//
//   - Same redacted body. Every value written comes from the already-redacted
//     output.Finding, which has no raw-secret field, so the never-store-raw
//     invariant holds for free: a SARIF document can never contain a usable secret.
//     The redacted/fingerprint values land in result.partialFingerprints, exactly
//     the SARIF-native home for a stable dedup identity.
//   - Never block the pipeline. Emit only appends to an in-memory slice under a
//     mutex; the (potentially larger) write happens once, at Close.
//   - Fail safely. Close creates the parent directory and writes atomically via a
//     temp file + rename so a crash mid-write never leaves a half-written document
//     that a downstream SARIF consumer would choke on.
package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/bugsyhewitt/seance/internal/output"
)

// schemaURI and version pin the SARIF 2.1.0 OASIS schema that GitHub code
// scanning and other consumers validate against.
const (
	schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	version   = "2.1.0"

	toolName    = "seance"
	toolInfoURI = "https://github.com/bugsyhewitt/seance"
)

// Sink accumulates Findings and, on Close, writes a single SARIF 2.1.0 document.
type Sink struct {
	path    string
	version string // séance build version, recorded as tool.driver.version

	mu       sync.Mutex
	findings []output.Finding
	closed   bool
}

// New returns a SARIF sink that will write its document to path on Close. The
// version string is recorded as the tool driver version in the report (pass the
// séance build version; "" is acceptable and simply omits the field).
func New(path, version string) *Sink {
	return &Sink{path: path, version: version}
}

// Emit implements output.Sink. It buffers the (already-redacted) Finding for
// inclusion in the SARIF document written at Close. It never blocks on I/O.
func (s *Sink) Emit(_ context.Context, finding output.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.findings = append(s.findings, finding)
	return nil
}

// Close serializes the buffered findings into a SARIF 2.1.0 document and writes
// it to the configured path. It is idempotent: a second call is a no-op. The
// parent directory is created if missing and the write is atomic (temp file +
// rename) so a partially written report is never observable.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	doc := s.build()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	data = append(data, '\n')

	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create sarif dir %q: %w", dir, err)
		}
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write sarif %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize sarif %q: %w", s.path, err)
	}
	return nil
}

// build assembles the in-memory SARIF document from the buffered findings. Rules
// are de-duplicated into the tool driver's rule catalog; each finding becomes one
// result that references its rule by index. Caller must hold s.mu.
func (s *Sink) build() document {
	// Stable rule catalog: one entry per distinct RuleID, in first-seen order,
	// with each result's ruleIndex pointing into it (SARIF's normalized form).
	ruleIndex := make(map[string]int)
	// Both slices are initialized non-nil so a clean (zero-finding) run still
	// serializes `"rules": []` and `"results": []` rather than `null`, keeping the
	// document valid for strict SARIF consumers.
	rules := make([]reportingDescriptor, 0, len(s.findings))
	results := make([]result, 0, len(s.findings))

	for _, f := range s.findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, reportingDescriptor{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: &message{Text: ruleText(f)},
			})
		}
		results = append(results, findingToResult(f, idx))
	}

	driver := toolComponent{
		Name:           toolName,
		Version:        s.version,
		InformationURI: toolInfoURI,
		Rules:          rules,
	}

	return document{
		Schema:  schemaURI,
		Version: version,
		Runs: []run{{
			Tool:    tool{Driver: driver},
			Results: results,
		}},
	}
}

// ruleText returns a human description for a rule's catalog entry, preferring the
// rule's own description and falling back to its ID.
func ruleText(f output.Finding) string {
	if f.RuleDesc != "" {
		return f.RuleDesc
	}
	return f.RuleID
}

// findingToResult maps one redacted Finding to a SARIF result. Only redacted /
// locator fields are used — no raw secret material exists on Finding to leak. The
// repo and commit are encoded into the artifact URI so a triager can navigate
// straight to the leak's source.
func findingToResult(f output.Finding, ruleIdx int) result {
	r := result{
		RuleID:    f.RuleID,
		RuleIndex: ruleIdx,
		Level:     levelForConfidence(f.Confidence),
		Message:   message{Text: resultMessage(f)},
		Locations: []location{{
			PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: artifactURI(f)},
				Region:           regionForLine(f.LineNumber),
			},
		}},
	}

	// partialFingerprints is the SARIF-native home for a stable dedup identity.
	// Both values are privacy-preserving (redacted / hashed), never raw secrets.
	pf := make(map[string]string, 2)
	if f.Fingerprint != "" {
		pf["seanceFingerprint"] = f.Fingerprint
	}
	if f.Redacted != "" {
		pf["seanceRedacted"] = f.Redacted
	}
	if len(pf) > 0 {
		r.PartialFingerprints = pf
	}

	// Surface séance's 0-1 confidence as a property so consumers can sort/filter
	// by signal strength, and carry the rule tags through.
	props := map[string]any{"confidence": f.Confidence}
	if f.Provider != "" {
		props["provider"] = f.Provider
	}
	if f.CommitSHA != "" {
		props["commitSha"] = f.CommitSHA
	}
	if len(f.Tags) > 0 {
		props["tags"] = f.Tags
	}
	r.Properties = props

	return r
}

// levelForConfidence maps séance's 0-1 confidence onto SARIF's result.level
// vocabulary. SARIF has no numeric severity on result (that lives in properties),
// so we bucket: high confidence is an "error", medium a "warning", low a "note".
func levelForConfidence(c float64) string {
	switch {
	case c >= 0.8:
		return "error"
	case c >= 0.5:
		return "warning"
	default:
		return "note"
	}
}

// artifactURI encodes the repo and commit into the artifact location so the
// result points at the exact source of the leak. It is intentionally a logical
// URI (not a fetchable file:// path) — séance scans remote commits, not a local
// checkout.
func artifactURI(f output.Finding) string {
	owner := f.RepoOwner
	repo := f.RepoName
	path := f.FilePath
	switch {
	case owner != "" && repo != "" && f.CommitSHA != "":
		return fmt.Sprintf("%s/%s/blob/%s/%s", owner, repo, f.CommitSHA, path)
	case owner != "" && repo != "":
		return fmt.Sprintf("%s/%s/%s", owner, repo, path)
	default:
		return path
	}
}

// resultMessage is the per-result human message. It names the rule, the location,
// and the redacted value — never the raw secret.
func resultMessage(f output.Finding) string {
	desc := f.RuleDesc
	if desc == "" {
		desc = f.RuleID
	}
	loc := f.FilePath
	if f.RepoOwner != "" && f.RepoName != "" {
		loc = fmt.Sprintf("%s/%s:%s", f.RepoOwner, f.RepoName, f.FilePath)
	}
	if f.Redacted != "" {
		return fmt.Sprintf("%s detected in %s (redacted: %s)", desc, loc, f.Redacted)
	}
	return fmt.Sprintf("%s detected in %s", desc, loc)
}

// regionForLine returns a SARIF region for a 1-based line number, or nil when the
// line is unknown (0). SARIF startLine is 1-based, matching séance's LineNumber.
func regionForLine(line int) *region {
	if line <= 0 {
		return nil
	}
	return &region{StartLine: line}
}

// SortFindings is exposed for tests/callers that want a deterministic ordering of
// the buffered findings before Close (the document otherwise preserves Emit order,
// which is already deterministic for a given run). It sorts by repo, file, line,
// then rule.
func SortFindings(fs []output.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.RepoOwner != b.RepoOwner {
			return a.RepoOwner < b.RepoOwner
		}
		if a.RepoName != b.RepoName {
			return a.RepoName < b.RepoName
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		return a.RuleID < b.RuleID
	})
}

// --- SARIF 2.1.0 document model (minimal subset séance emits) ---

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver toolComponent `json:"driver"`
}

type toolComponent struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []reportingDescriptor `json:"rules"`
}

type reportingDescriptor struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	ShortDescription *message `json:"shortDescription,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}
