package scan_test

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/seance/internal/output"
	"github.com/bugsyhewitt/seance/internal/scan"
)

func baseFinding() output.Finding {
	return output.Finding{
		RuleID:    "aws-access-key-id",
		Redacted:  "sha256:deadbeef",
		RepoOwner: "alice",
		RepoName:  "repo",
		FilePath:  ".env",
		// CommitSHA / LineNumber deliberately excluded from the fingerprint: the
		// same secret re-pushed in a new commit must collide.
		CommitSHA:  "commit-1",
		LineNumber: 7,
	}
}

// TestFingerprint_StableForIdentical proves the dedup key is stable across runs:
// identical (rule, redacted, repo, file) inputs yield the same fingerprint even
// when commit SHA and line number differ — exactly the re-leak case.
func TestFingerprint_StableForIdentical(t *testing.T) {
	a := baseFinding()
	b := baseFinding()
	b.CommitSHA = "commit-2" // re-pushed in a different commit
	b.LineNumber = 42        // moved within the file

	if scan.Fingerprint(a) != scan.Fingerprint(b) {
		t.Error("same secret in same location must produce the same fingerprint regardless of commit/line")
	}
}

// TestFingerprint_DistinctFields verifies each identity component changes the
// fingerprint, so two genuinely different findings never alias.
func TestFingerprint_DistinctFields(t *testing.T) {
	base := scan.Fingerprint(baseFinding())

	mutators := map[string]func(*output.Finding){
		"rule":     func(f *output.Finding) { f.RuleID = "other-rule" },
		"redacted": func(f *output.Finding) { f.Redacted = "sha256:cafef00d" },
		"owner":    func(f *output.Finding) { f.RepoOwner = "bob" },
		"repo":     func(f *output.Finding) { f.RepoName = "other" },
		"path":     func(f *output.Finding) { f.FilePath = "config.yml" },
	}
	for name, mut := range mutators {
		f := baseFinding()
		mut(&f)
		if scan.Fingerprint(f) == base {
			t.Errorf("changing %s must change the fingerprint", name)
		}
	}
}

// TestFingerprint_NoFieldAliasing guards against the classic concatenation bug
// where ("ab","c") and ("a","bc") collide. The NUL separator must prevent this.
func TestFingerprint_NoFieldAliasing(t *testing.T) {
	x := baseFinding()
	x.RepoOwner = "ab"
	x.RepoName = "c"

	y := baseFinding()
	y.RepoOwner = "a"
	y.RepoName = "bc"

	if scan.Fingerprint(x) == scan.Fingerprint(y) {
		t.Error("field boundaries must not alias — separator missing or weak")
	}
}

// TestFingerprint_PrivacyPreserving asserts the fingerprint is an opaque hash and
// never embeds the locator material verbatim — it can be persisted and shared
// safely. (Raw secret bytes are already excluded by construction; this checks the
// human-readable locator fields too.)
func TestFingerprint_PrivacyPreserving(t *testing.T) {
	f := baseFinding()
	fp := scan.Fingerprint(f)

	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint should be a labelled sha256 hash, got %q", fp)
	}
	for _, raw := range []string{f.RepoOwner, f.RepoName, f.FilePath, f.RuleID} {
		if strings.Contains(fp, raw) {
			t.Errorf("fingerprint %q must not embed locator field %q verbatim", fp, raw)
		}
	}
}
