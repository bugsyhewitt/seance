package scan

import (
	"crypto/sha256"
	"fmt"

	"github.com/bugsyhewitt/seance/internal/output"
)

// Fingerprint returns a stable, privacy-preserving identifier for a finding,
// computed from (rule_id, redacted, repo_owner, repo_name, file_path).
//
// It is the cross-run dedup key and the value operators copy into a
// --suppress-file entry. The inputs are all redacted/locator material — the
// Redacted field is already a masked or SHA-256-derived value, never raw secret
// bytes — so the fingerprint can be persisted, logged, and shared without ever
// leaking a credential. The same secret in the same file produces the same
// fingerprint across runs, forks, and re-pushes, so re-leaks collide correctly.
//
// The component separator (a NUL byte) cannot appear in any of the fields, so
// the join is unambiguous and two distinct findings cannot alias.
func Fingerprint(f output.Finding) string {
	const sep = "\x00"
	h := sha256.Sum256([]byte(
		f.RuleID + sep +
			f.Redacted + sep +
			f.RepoOwner + sep +
			f.RepoName + sep +
			f.FilePath,
	))
	return fmt.Sprintf("sha256:%x", h[:])
}
