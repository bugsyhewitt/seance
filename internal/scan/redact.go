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
