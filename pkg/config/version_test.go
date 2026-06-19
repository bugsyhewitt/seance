// pkg/config/version_test.go
//
// Pins the v1.0 release contract for seance:
//   (1) Defaults().Version must equal "1.0.0" (was "0.1.0-dev" pre-release).
//   (2) CHANGELOG.md must contain a "## [1.0.0]" entry.
//
// If either regresses, the v1.0 flip is no longer valid — fail the build.
package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDefaults_VersionIsV1_0_0(t *testing.T) {
	got := Defaults().Version
	want := "1.0.0"
	if got != want {
		t.Errorf("Defaults().Version = %q, want %q (v1.0 release contract)", got, want)
	}
}

func TestCHANGELOG_HasV1_0_0Entry(t *testing.T) {
	// pkg/config/version_test.go -> ../../CHANGELOG.md -> repo root
	const rel = "../../CHANGELOG.md"
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^## \[1\.0\.0\]`)
	if !re.MatchString(string(data)) {
		t.Errorf("CHANGELOG.md missing v1.0.0 entry header (pattern %q not found)", re.String())
	}
	// sanity: ensure no Unreleased v0.2 WIP header remains at the top
	if strings.Contains(string(data), "## [Unreleased] — v0.2 in progress") {
		t.Errorf("CHANGELOG.md still contains the [Unreleased] v0.2 WIP header; the v1.0 RELEASE must absorb it under [1.0.0]")
	}
}
