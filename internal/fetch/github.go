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

// GitHubFetcher retrieves commit diff content from the GitHub API.
type GitHubFetcher struct {
	token   string
	baseURL string
	client  *http.Client
}

// NewGitHubFetcher returns a fetcher. baseURL is the GitHub API root (overridable in tests).
func NewGitHubFetcher(token, baseURL string) *GitHubFetcher {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubFetcher{
		token:   token,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch retrieves the diff patch for a single file in a commit.
func (f *GitHubFetcher) Fetch(ctx context.Context, event ingestion.CommitEvent, ref ingestion.FileRef) (FileContent, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
		f.baseURL, event.RepoOwner, event.RepoName, event.CommitSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "request error: " + err.Error()}, nil
	}
	req.Header.Set("User-Agent", "seance/0.1 (+https://github.com/bugsyhewitt/seance)")
	req.Header.Set("Accept", "application/vnd.github+json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "fetch error: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}

	var payload struct {
		Files []struct {
			Filename string `json:"filename"`
			Patch    string `json:"patch"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "decode error"}, nil
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

// FetchAll retrieves diff patches for all changed files in a commit.
// One HTTP request returns diffs for all files; callers should apply path-based
// filtering on the results to stay within rate-limit budget.
func (f *GitHubFetcher) FetchAll(ctx context.Context, event ingestion.CommitEvent) ([]FileContent, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
		f.baseURL, event.RepoOwner, event.RepoName, event.CommitSHA)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "seance/0.1 (+https://github.com/bugsyhewitt/seance)")
	req.Header.Set("Accept", "application/vnd.github+json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil // non-200 treated as transient; caller skips this commit
	}

	var payload struct {
		Files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
			Patch    string `json:"patch"`
		} `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil
	}

	results := make([]FileContent, 0, len(payload.Files))
	for _, file := range payload.Files {
		ref := ingestion.FileRef{Path: file.Filename, Status: file.Status}
		switch {
		case file.Status == "removed":
			results = append(results, FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "removed"})
		case len(file.Patch) == 0:
			results = append(results, FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "empty patch"})
		case len(file.Patch) > maxPatchBytes:
			results = append(results, FileContent{Event: event, FileRef: ref, Skipped: true, SkipReason: "patch too large"})
		default:
			results = append(results, FileContent{
				Event:   event,
				FileRef: ref,
				Patch:   file.Patch,
				Lines:   strings.Split(file.Patch, "\n"),
			})
		}
	}
	return results, nil
}
