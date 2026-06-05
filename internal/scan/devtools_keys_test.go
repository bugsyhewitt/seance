package scan_test

// Tests for five new developer-tool / cloud-native credential rules shipped in
// Rotation 37:
//   - hashicorp-vault-token  (hvs./hvb. prefix)
//   - databricks-pat          (dapi + 32 hex chars)
//   - grafana-cloud-api-key   (glc_ prefix + base64 body)
//   - linear-api-key          (lin_api_ prefix + 40+ alphanums)
//   - doppler-service-token   (dp.st. prefix + 43 alphanums)
//
// Every synthetic token below is fabricated: it matches the issuer's documented
// prefix/format but is not a live credential. Tokens with platform-recognised
// prefix shapes are assembled from fragments to avoid GitHub push-protection
// false-positives on test data in a public repo.

import (
	"strings"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────────

// alphaBody32 is a high-entropy 32-char alphanumeric string used as a fake
// credential body in several tests. All lowercase hex for databricks; mixed for
// the others.
const (
	hexBody32   = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" // 32 hex chars — databricks body
	alpha40Body = "Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX4cV6nM" // 40+ alphanum
)

// ── Vault ────────────────────────────────────────────────────────────────────

func TestDefaultRuleset_DetectsVaultServiceToken(t *testing.T) {
	// hvs. prefix = Vault service token (HCP Vault, Vault OSS ≥1.10).
	// Built as "hvs." + separator + body to keep the literal prefix off the
	// scanned line and avoid push-protection on the test file itself.
	prefix := "hvs" + "."
	body := "AeXb2Qm7Rz4Lp9Wn5Vd8Yc3Hf0Jg6kS1m"
	line := "VAULT_TOKEN=" + prefix + body
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "hashicorp-vault-token"); !ok {
		t.Fatalf("vault service token not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DetectsVaultBatchToken(t *testing.T) {
	// hvb. prefix = Vault batch token.
	prefix := "hvb" + "."
	body := "B3Xz1Km8Rq5Lp2Wn9Vd4Yc7Hf0Jg3kS6mQ0"
	line := "VAULT_TOKEN=" + prefix + body
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "hashicorp-vault-token"); !ok {
		t.Fatalf("vault batch token not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_VaultTokenNoFalsePositiveOnShortString(t *testing.T) {
	// A short string that starts with hvs. but is less than 24 chars in the body
	// should not match (too short for a real Vault token).
	line := "VAULT_TOKEN=hvs.shorttoken"
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "hashicorp-vault-token"); ok {
		t.Errorf("vault rule false-positived on short token; findings=%+v", findings)
	}
}

func TestDefaultRuleset_VaultTokenRedacted(t *testing.T) {
	prefix := "hvs" + "."
	body := "AeXb2Qm7Rz4Lp9Wn5Vd8Yc3Hf0Jg6kS1mNpT"
	secret := prefix + body
	line := "export VAULT_TOKEN=" + secret
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "hashicorp-vault-token")
	if !ok {
		t.Fatalf("vault token not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw token")
	}
}

// ── Databricks ────────────────────────────────────────────────────────────────

func TestDefaultRuleset_DetectsDatabricksPAT(t *testing.T) {
	// dapi + 32 lowercase hex chars.
	token := "dapi" + hexBody32
	line := "DATABRICKS_TOKEN=" + token
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "databricks-pat"); !ok {
		t.Fatalf("databricks PAT not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DatabricksPATNoFalsePositiveOnShortHex(t *testing.T) {
	// dapi + only 16 hex chars — too short.
	line := "DATABRICKS_TOKEN=dapia1b2c3d4e5f6a7b8"
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "databricks-pat"); ok {
		t.Errorf("databricks rule false-positived on short token; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DatabricksPATRedacted(t *testing.T) {
	token := "dapi" + hexBody32
	line := "token = " + `"` + token + `"`
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "databricks-pat")
	if !ok {
		t.Fatalf("databricks PAT not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, token) {
		t.Error("redacted output must not contain the raw token")
	}
}

// ── Grafana ────────────────────────────────────────────────────────────────────

func TestDefaultRuleset_DetectsGrafanaCloudAPIKey(t *testing.T) {
	// glc_ + base64 body. Assembled from fragments to avoid push protection.
	prefix := "glc" + "_"
	body := "eyJuIjoiZGV2LXdvcmtlciIsImkiOjEyMzQ1NiwidCI6Mn0="
	line := "GF_CLOUD_API_KEY=" + prefix + body
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "grafana-cloud-api-key"); !ok {
		t.Fatalf("grafana cloud api key not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_GrafanaAPIKeyRedacted(t *testing.T) {
	prefix := "glc" + "_"
	body := "eyJuIjoiZGV2LXdvcmtlciIsImkiOjEyMzQ1NiwidCI6Mn0="
	secret := prefix + body
	line := "GRAFANA_API_KEY=" + secret
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "grafana-cloud-api-key")
	if !ok {
		t.Fatalf("grafana api key not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw key")
	}
}

func TestDefaultRuleset_GrafanaAPIKeyNoFalsePositiveOnProse(t *testing.T) {
	line := "We use Grafana Cloud for monitoring dashboards and alerting."
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "grafana-cloud-api-key"); ok {
		t.Errorf("grafana rule false-positived on prose; findings=%+v", findings)
	}
}

// ── Linear ────────────────────────────────────────────────────────────────────

func TestDefaultRuleset_DetectsLinearAPIKey(t *testing.T) {
	// lin_api_ + 40+ alphanumeric chars.
	// Assembled from parts to avoid push-protection tripping on the test file.
	prefix := "lin" + "_api_"
	body := alpha40Body
	line := "LINEAR_API_KEY=" + prefix + body
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "linear-api-key"); !ok {
		t.Fatalf("linear api key not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_LinearAPIKeyNoFalsePositiveOnShortBody(t *testing.T) {
	// lin_api_ + only 20 chars — under the 40-char minimum.
	line := "LINEAR_API_KEY=lin_api_Qb7Xz2Lm9Rt4Kp8Wn3V"
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "linear-api-key"); ok {
		t.Errorf("linear rule false-positived on short body; findings=%+v", findings)
	}
}

func TestDefaultRuleset_LinearAPIKeyRedacted(t *testing.T) {
	prefix := "lin" + "_api_"
	body := alpha40Body
	secret := prefix + body
	line := `api_key = "` + secret + `"`
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "linear-api-key")
	if !ok {
		t.Fatalf("linear api key not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw key")
	}
}

// ── Doppler ───────────────────────────────────────────────────────────────────

func TestDefaultRuleset_DetectsDopplerServiceToken(t *testing.T) {
	// dp.st. + exactly 43 alphanumeric chars.
	prefix := "dp" + ".st."
	body := "Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX4cV6nM4k" // 43 chars
	line := "DOPPLER_TOKEN=" + prefix + body
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "doppler-service-token"); !ok {
		t.Fatalf("doppler service token not detected; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DopplerTokenNoFalsePositiveOnShortBody(t *testing.T) {
	// dp.st. + only 20 chars — under the 43-char exact length.
	line := "DOPPLER_TOKEN=dp.st.Qb7Xz2Lm9Rt4Kp8Wn3V"
	findings := scanLine(t, line)
	if _, ok := findByRule(findings, "doppler-service-token"); ok {
		t.Errorf("doppler rule false-positived on short body; findings=%+v", findings)
	}
}

func TestDefaultRuleset_DopplerTokenRedacted(t *testing.T) {
	prefix := "dp" + ".st."
	body := "Qb7Xz2Lm9Rt4Kp8Wn3Vd6Yc1Hf5Jg0aZ2bX4cV6nM4k" // 43 chars
	secret := prefix + body
	line := `DOPPLER_TOKEN=` + secret
	findings := scanLine(t, line)
	f, ok := findByRule(findings, "doppler-service-token")
	if !ok {
		t.Fatalf("doppler service token not detected; findings=%+v", findings)
	}
	if strings.Contains(f.Redacted, secret) {
		t.Error("redacted output must not contain the raw token")
	}
}

// ── Cross-rule false-positive guard ──────────────────────────────────────────

func TestDefaultRuleset_NewRulesNoFalsePositiveOnDevToolsProse(t *testing.T) {
	// Ordinary prose mentioning these tools/platforms must not trip any new rule.
	lines := []string{
		"We use HashiCorp Vault for secrets management in our infrastructure.",
		"Our data pipelines run on Databricks.",
		"Grafana Cloud is our observability platform.",
		"We track issues in Linear and store config in Doppler.",
	}
	newRuleIDs := []string{
		"hashicorp-vault-token",
		"databricks-pat",
		"grafana-cloud-api-key",
		"linear-api-key",
		"doppler-service-token",
	}
	for _, line := range lines {
		findings := scanLine(t, line)
		for _, ruleID := range newRuleIDs {
			if _, ok := findByRule(findings, ruleID); ok {
				t.Errorf("rule %q false-positived on prose %q; findings=%+v", ruleID, line, findings)
			}
		}
	}
}
