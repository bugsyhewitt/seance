package scan

import "math"

// charset identifies commonly used high-entropy character classes for
// bonus scoring. It is intentionally broad — the goal is to distinguish
// random credential material from human-readable strings.
const (
	charsetHex    = "0123456789abcdefABCDEF"
	charsetBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	charsetBase62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// shannonEntropy computes the Shannon entropy (bits per character) of s.
// An empty string returns 0. A string where every character is the same
// returns 0. A uniform distribution over N distinct characters returns log2(N).
//
// Typical thresholds used in credential scanners:
//   - Hex secrets (e.g. auth tokens): ≥ 3.0
//   - Base64 secrets (e.g. AWS secret keys): ≥ 4.0
//   - Generic high-entropy strings: ≥ 3.5
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	total := 0
	for _, ch := range s {
		freq[ch]++
		total++
	}
	n := float64(total)
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyConfidenceBonus returns a confidence adjustment in [0, 0.15] based on
// how much the measured entropy exceeds the rule's minimum threshold.
// If rule.Entropy == 0 (disabled), returns 0.
// The bonus saturates at 1 bit of headroom above the threshold.
func entropyConfidenceBonus(measured, threshold float64) float64 {
	if threshold <= 0 {
		return 0
	}
	headroom := measured - threshold
	if headroom <= 0 {
		return 0
	}
	// Scale: 0 headroom → 0 bonus, 1.0 bit headroom → 0.15 bonus (saturates)
	if headroom > 1.0 {
		headroom = 1.0
	}
	return headroom * 0.15
}
