package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLicenseRequest_RoundTrip(t *testing.T) {
	fp := MachineFingerprint{
		Primary:         "fp:host:a1b2c3d4e5f67890",
		Platform:        PlatformHost,
		CanonicalDigest: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
		ShortDigest:     "a1b2c3d4e5f67890",
		Components: map[string]string{
			"os":          "linux",
			"arch":        "amd64",
			"machine_id":  "mock-machine-id-12345",
			"system_uuid": "mock-system-uuid-67890",
		},
		ResolvedAt: time.Now().UTC().Truncate(time.Second),
	}

	req := NewLicenseRequest("Acme Aerospace", "gitlab-fleet-governor", fp)
	req.Plan = "enterprise"
	req.RequestedLimits = map[string]int64{
		"runners": 500,
		"users":   1000,
	}
	req.RequestedFeatures = []string{"sso", "audit-logs", "high-availability"}
	req.Notes = "Air-gapped deployment in isolated VPC"

	// 1. Armored serialization
	armored, err := req.Armored()
	if err != nil {
		t.Fatalf("req.Armored() error = %v", err)
	}

	armoredStr := string(armored)
	if !strings.Contains(armoredStr, "-----BEGIN "+PEMTypeLicenseRequest+"-----") {
		t.Errorf("missing PEM header in armored output: %s", armoredStr)
	}
	if !strings.Contains(armoredStr, "-----END "+PEMTypeLicenseRequest+"-----") {
		t.Errorf("missing PEM footer in armored output: %s", armoredStr)
	}

	// 2. Armored deserialization
	parsed, err := ParseLicenseRequest(armored)
	if err != nil {
		t.Fatalf("ParseLicenseRequest(armored) error = %v", err)
	}

	if parsed.Customer != req.Customer {
		t.Errorf("Customer = %q, want %q", parsed.Customer, req.Customer)
	}
	if parsed.Product != req.Product {
		t.Errorf("Product = %q, want %q", parsed.Product, req.Product)
	}
	if parsed.Plan != req.Plan {
		t.Errorf("Plan = %q, want %q", parsed.Plan, req.Plan)
	}
	if parsed.Fingerprint.Primary != req.Fingerprint.Primary {
		t.Errorf("Fingerprint.Primary = %q, want %q", parsed.Fingerprint.Primary, req.Fingerprint.Primary)
	}
	if parsed.RequestedLimits["runners"] != 500 || parsed.RequestedLimits["users"] != 1000 {
		t.Errorf("unexpected limits: %+v", parsed.RequestedLimits)
	}
	if len(parsed.RequestedFeatures) != 3 {
		t.Errorf("expected 3 features, got %d", len(parsed.RequestedFeatures))
	}
	if parsed.Notes != req.Notes {
		t.Errorf("Notes = %q, want %q", parsed.Notes, req.Notes)
	}

	// 3. Format inspection card
	card := parsed.FormatCard()
	if !strings.Contains(card, "Acme Aerospace") || !strings.Contains(card, "gitlab-fleet-governor") {
		t.Errorf("card missing basic fields: %s", card)
	}
	if !strings.Contains(card, "fp:host:a1b2c3d4e5f67890") {
		t.Errorf("card missing primary fingerprint: %s", card)
	}
	if !strings.Contains(card, "runners") || !strings.Contains(card, "audit-logs") {
		t.Errorf("card missing entitlements: %s", card)
	}

	// 4. File round-trip
	tmpFile := filepath.Join(t.TempDir(), "request.divreq")
	if err := os.WriteFile(tmpFile, armored, 0600); err != nil {
		t.Fatal(err)
	}

	fromFile, err := ParseLicenseRequestFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseLicenseRequestFile() error = %v", err)
	}
	if fromFile.Customer != req.Customer {
		t.Errorf("file Customer = %q, want %q", fromFile.Customer, req.Customer)
	}
}

func TestLicenseRequest_Validation(t *testing.T) {
	fp := MachineFingerprint{Primary: "fp:host:test"}

	t.Run("empty customer", func(t *testing.T) {
		req := NewLicenseRequest("", "my-product", fp)
		if err := req.Validate(); err == nil {
			t.Fatal("expected error on empty customer")
		}
	})

	t.Run("empty product", func(t *testing.T) {
		req := NewLicenseRequest("Customer", "", fp)
		if err := req.Validate(); err == nil {
			t.Fatal("expected error on empty product")
		}
	})

	t.Run("missing fingerprint", func(t *testing.T) {
		req := NewLicenseRequest("Customer", "Product", MachineFingerprint{})
		if err := req.Validate(); err == nil {
			t.Fatal("expected error on missing fingerprint")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		var req *LicenseRequest
		if err := req.Validate(); err == nil {
			t.Fatal("expected error on nil request")
		}
		if req.FormatCard() != "No license request" {
			t.Errorf("unexpected card for nil: %q", req.FormatCard())
		}
	})

	t.Run("invalid pem type", func(t *testing.T) {
		invalidPEM := "-----BEGIN UNKNOWN BLOCK-----\ne30=\n-----END UNKNOWN BLOCK-----\n"
		_, err := ParseLicenseRequest([]byte(invalidPEM))
		if err == nil {
			t.Fatal("expected error on invalid PEM block type")
		}
	})
}
