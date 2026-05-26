package scan

import (
	"math"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("empty string: want 0, got %f", got)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	// All same characters → entropy 0
	if got := shannonEntropy("aaaaaaaaaa"); got != 0 {
		t.Errorf("single distinct char: want 0, got %f", got)
	}
}

func TestShannonEntropy_TwoChars(t *testing.T) {
	// Uniform over 2 chars → entropy = 1.0 bit
	got := shannonEntropy("abababab")
	if math.Abs(got-1.0) > 0.01 {
		t.Errorf("two-char uniform: want ~1.0, got %f", got)
	}
}

func TestShannonEntropy_HighEntropy(t *testing.T) {
	// A random-looking AWS-style key should exceed 4.0 bits
	key := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	got := shannonEntropy(key)
	if got < 4.0 {
		t.Errorf("high-entropy key: want > 4.0, got %f", got)
	}
}

func TestShannonEntropy_LowEntropy(t *testing.T) {
	// A placeholder-like value should be below 3.0 bits
	placeholder := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	got := shannonEntropy(placeholder)
	if got >= 3.0 {
		t.Errorf("low-entropy placeholder: want < 3.0, got %f", got)
	}
}

func TestEntropyConfidenceBonus_Zero(t *testing.T) {
	if got := entropyConfidenceBonus(5.0, 0); got != 0 {
		t.Errorf("threshold=0 should return 0, got %f", got)
	}
}

func TestEntropyConfidenceBonus_BelowThreshold(t *testing.T) {
	if got := entropyConfidenceBonus(2.5, 3.5); got != 0 {
		t.Errorf("measured < threshold should return 0, got %f", got)
	}
}

func TestEntropyConfidenceBonus_AtThreshold(t *testing.T) {
	if got := entropyConfidenceBonus(3.5, 3.5); got != 0 {
		t.Errorf("measured == threshold should return 0, got %f", got)
	}
}

func TestEntropyConfidenceBonus_MaxSaturation(t *testing.T) {
	// headroom ≥ 1.0 bit saturates at 0.15
	got := entropyConfidenceBonus(6.0, 3.5)
	if math.Abs(got-0.15) > 0.001 {
		t.Errorf("saturated bonus: want 0.15, got %f", got)
	}
}

func TestEntropyConfidenceBonus_HalfPoint(t *testing.T) {
	// headroom = 0.5 → bonus = 0.5 * 0.15 = 0.075
	got := entropyConfidenceBonus(4.0, 3.5)
	if math.Abs(got-0.075) > 0.001 {
		t.Errorf("half-point bonus: want 0.075, got %f", got)
	}
}
