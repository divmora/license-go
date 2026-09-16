package license

import (
	"strings"
	"testing"
	"time"
)

func TestClaims_FormatInspect_Nil(t *testing.T) {
	var c *Claims
	out := c.FormatInspect()
	if !strings.Contains(out, "No license claims to inspect") {
		t.Errorf("expected 'No license claims to inspect', got: %q", out)
	}
}

func TestClaims_FormatInspect_FullEnterprise(t *testing.T) {
	refTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	issued := refTime.Add(-10 * 24 * time.Hour)
	notBefore := issued
	expires := refTime.Add(20 * 24 * time.Hour)
	maintenance := refTime.Add(365 * 24 * time.Hour)

	c := &Claims{
		ID:    "lic-enterprise-001",
		KeyID: "divmora-2026-root",
		Customer: Customer{
			Name:  "Acme Corporation",
			Email: "secops@acme.com",
			OrgID: "org_acme_123",
		},
		Product:              "gitlab-fleet-governor",
		Plan:                 "enterprise",
		IssuedAt:             issued,
		NotBefore:            notBefore,
		ExpiresAt:            expires,
		GracePeriodDays:      14,
		MaxVersion:           "1.*",
		AllowedVersions:      []string{"1.*", "2.0.*"},
		MaintenanceExpiresAt: maintenance,
		Features:             []string{"sso", "ha", "audit-logs"},
		Limits: map[string]int64{
			"max_nodes":      50,
			"max_runners":    200,
			"unlimited_runs": -1,
		},
		Environment: "production",
		Fingerprint: "sha256:abcd1234efgh5678",
		Scope: &Scope{
			Environments: []string{"production", "staging"},
			Accounts:     []string{"123456789012"},
			Regions:      []string{"us-east-1", "eu-west-1"},
			Clusters:     []string{"prod-eks-01"},
			Namespaces:   []string{"gitlab.com/acme/*"},
			Hosts:        []string{"*.acme.corp"},
			Custom: map[string][]string{
				"tier":       {"platinum", "gold"},
				"datacenter": {"dc-east", "dc-west"},
			},
		},
		Metadata: map[string]string{
			"billing_id": "inv-9981",
			"contact":    "admin@acme.com",
		},
	}

	out := c.FormatInspectAt(refTime)

	expectedSnippets := []string{
		"DIVMORA LICENSE CLAIMS",
		"Status:                  Active (20 days remaining, expires " + expires.Format(time.RFC3339) + ")",
		"Product:                 gitlab-fleet-governor",
		"Plan / Tier:             enterprise",
		"License ID:              lic-enterprise-001",
		"Signing Key ID:          divmora-2026-root",
		"CUSTOMER",
		"Name:                  Acme Corporation",
		"Email:                 secops@acme.com",
		"Org ID:                org_acme_123",
		"VALIDITY TIMELINE",
		"Issued At:             " + issued.Format(time.RFC3339),
		"Valid From:            " + notBefore.Format(time.RFC3339),
		"Expires At:            " + expires.Format(time.RFC3339),
		"Grace Period:          14 days (cutoff: " + c.EffectiveExpiration().Format(time.RFC3339) + ")",
		"VERSION & MAINTENANCE",
		"Max Version:           1.*",
		"Allowed Versions:      1.*, 2.0.*",
		"Maintenance Cutoff:    " + maintenance.Format(time.RFC3339),
		"ENTITLEMENTS & QUOTAS",
		"Features:              audit-logs, ha, sso", // Alphabetical
		"• max_nodes:           50",
		"• max_runners:         200",
		"• unlimited_runs:      Unlimited (-1)",
		"OPERATIONAL SCOPE",
		"Environment:           production",
		"Node Fingerprint:      sha256:abcd1234efgh5678",
		"Environments:          production, staging",
		"Accounts:              123456789012",
		"Regions:               us-east-1, eu-west-1",
		"Clusters:              prod-eks-01",
		"Namespaces:            gitlab.com/acme/*",
		"Hosts:                 *.acme.corp",
		"• datacenter:          dc-east, dc-west",
		"• tier:                platinum, gold",
		"METADATA",
		"• billing_id:            inv-9981",
		"• contact:               admin@acme.com",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(out, snippet) {
			t.Errorf("FormatInspect output missing snippet %q\nFull output:\n%s", snippet, out)
		}
	}
}

func TestClaims_FormatInspect_Perpetual(t *testing.T) {
	c := &Claims{
		Product:  "otel-aws-log-processor",
		Plan:     "starter",
		Customer: Customer{Name: "Globex"},
	}

	out := c.FormatInspect()

	if !strings.Contains(out, "Status:                  Perpetual license (does not expire)") {
		t.Errorf("expected perpetual status line, got:\n%s", out)
	}
	if !strings.Contains(out, "Expires At:            Perpetual (Does not expire)") {
		t.Errorf("expected perpetual expires line, got:\n%s", out)
	}
	if strings.Contains(out, "Grace Period:") {
		t.Errorf("perpetual license should not show grace period, got:\n%s", out)
	}
	if strings.Contains(out, "VERSION & MAINTENANCE") {
		t.Errorf("unconstrained perpetual license should not show version section, got:\n%s", out)
	}
	if !strings.Contains(out, "Features:              (none)") {
		t.Errorf("expected (none) for features, got:\n%s", out)
	}
	if !strings.Contains(out, "Limits:                (unrestricted)") {
		t.Errorf("expected (unrestricted) for limits, got:\n%s", out)
	}
}

func TestClaims_FormatInspect_WildcardFeatures(t *testing.T) {
	c := &Claims{
		Product:  "gitlab-fleet-governor",
		Customer: Customer{Name: "AllFeaturesCorp"},
		Features: []string{"*"},
	}
	out := c.FormatInspect()
	if !strings.Contains(out, "Features:              * (All features entitled)") {
		t.Errorf("expected wildcard features line, got:\n%s", out)
	}
}

func TestVerificationResult_FormatInspect(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		var r *VerificationResult
		out := r.FormatInspect()
		if !strings.Contains(out, "No verification result to inspect") {
			t.Errorf("expected nil result message, got: %q", out)
		}
	})

	t.Run("verified result with clock attestation and key info", func(t *testing.T) {
		refTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		claims := &Claims{
			ID:       "lic-100",
			Product:  "gitlab-fleet-governor",
			Plan:     "pro",
			Customer: Customer{Name: "Initech"},
		}

		res := &VerificationResult{
			Claims:              claims,
			Status:              StatusActive,
			VerifiedByKeyID:     "sha256:feedbeef1234",
			VerifiedByKeyStatus: KeyStatusActive,
			EffectiveLicense:    "BSL-1.1",
			ServerTimeAttested:  true,
			ServerTime:          refTime,
			ClockSkew:           150 * time.Millisecond,
			EvaluationTime:      refTime,
		}

		out := res.FormatInspect()

		expectedSnippets := []string{
			"DIVMORA LICENSE VERIFICATION RESULT",
			"Status:                  Perpetual license (does not expire)",
			"Verified By Key:         sha256:feedbeef1234 (Status: ACTIVE)",
			"Server Time:             2026-06-15T12:00:00Z (Skew: 150ms)",
			"DIVMORA LICENSE CLAIMS",
			"Name:                  Initech",
			"Product:                 gitlab-fleet-governor",
		}

		for _, snippet := range expectedSnippets {
			if !strings.Contains(out, snippet) {
				t.Errorf("VerificationResult.FormatInspect() missing snippet %q\nFull output:\n%s", snippet, out)
			}
		}
	})

	t.Run("BSL converted result without claims", func(t *testing.T) {
		changeDate := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		res := &VerificationResult{
			BSLConverted:     true,
			EffectiveLicense: "Apache-2.0",
			ChangeDate:       changeDate,
		}

		out := res.FormatInspect()
		if !strings.Contains(out, "Governing License:       Apache-2.0 (Converted on 2026-01-01)") {
			t.Errorf("expected BSL converted license line, got:\n%s", out)
		}
	})
}
