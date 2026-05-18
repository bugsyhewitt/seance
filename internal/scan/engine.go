// Package scan runs the signature engine over fetched file content.
package scan

import (
	"context"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/seance/internal/fetch"
	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan/ruleset"
)

// Engine runs detection rules over fetched file content.
type Engine struct {
	rules []ruleset.Rule
	sinks []output.Sink
}

// New constructs an Engine with the given rules and output sinks.
func New(rules []ruleset.Rule, sinks ...output.Sink) *Engine {
	return &Engine{rules: rules, sinks: sinks}
}

// Scan runs all rules against content and emits Findings to all sinks.
// Returns the number of findings emitted.
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
