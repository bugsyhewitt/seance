package main

import "testing"

// TestDescribeWatchWindow verifies the human-readable startup-log description of
// the committer-date scoping window for each window shape. The caller only
// invokes this helper when at least one bound is set, so the all-empty case is
// not exercised here.
func TestDescribeWatchWindow(t *testing.T) {
	cases := []struct {
		name  string
		since string
		until string
		want  string
	}{
		{"both bounds", "2026-01-01", "2026-03-01", "2026-01-01..2026-03-01"},
		{"since only", "2026-01-01", "", "on or after 2026-01-01"},
		{"until only", "", "2026-03-01", "on or before 2026-03-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeWatchWindow(tc.since, tc.until); got != tc.want {
				t.Errorf("describeWatchWindow(%q,%q) = %q, want %q", tc.since, tc.until, got, tc.want)
			}
		})
	}
}
