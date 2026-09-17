package license_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func TestClaims_ValidateClaimsSchema_RequiredFields(t *testing.T) {
	now := time.Now().UTC()

	baseClaims := func() license.Claims {
		return license.Claims{
			ID: "550e8400-e29b-41d4-a716-446655440000",
			Customer: license.Customer{
				Name:  "Acme Corp",
				Email: "admin@acme.com",
			},
			Product:  "gitlab-fleet-governor",
			Plan:     "enterprise",
			IssuedAt: now,
		}
	}

	// Valid claims
	valid := baseClaims()
	if err := valid.ValidateClaimsSchema(); err != nil {
		t.Fatalf("expected valid claims to pass schema validation: %v", err)
	}

	// Missing ID
	noID := baseClaims()
	noID.ID = ""
	err := noID.ValidateClaimsSchema()
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.id is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing id, got: %v", err)
	}

	// Missing Customer Name
	noCust := baseClaims()
	noCust.Customer.Name = ""
	err = noCust.ValidateClaimsSchema()
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.customer.name is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing customer name, got: %v", err)
	}

	// Missing Product
	noProd := baseClaims()
	noProd.Product = ""
	err = noProd.ValidateClaimsSchema()
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.product is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing product, got: %v", err)
	}

	// Missing Plan
	noPlan := baseClaims()
	noPlan.Plan = ""
	err = noPlan.ValidateClaimsSchema()
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.plan is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing plan, got: %v", err)
	}

	// Missing IssuedAt
	noIssuedAt := baseClaims()
	noIssuedAt.IssuedAt = time.Time{}
	err = noIssuedAt.ValidateClaimsSchema()
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.issued_at is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing issued_at, got: %v", err)
	}
}

func TestClaims_ValidateClaimsSchema_EmailFormat(t *testing.T) {
	now := time.Now().UTC()
	makeClaims := func(email string) license.Claims {
		return license.Claims{
			ID: "550e8400-e29b-41d4-a716-446655440000",
			Customer: license.Customer{
				Name:  "Acme Corp",
				Email: email,
			},
			Product:  "gitlab-fleet-governor",
			Plan:     "enterprise",
			IssuedAt: now,
		}
	}

	validEmails := []string{
		"", // optional field
		"admin@example.com",
		"ops.team+alerts@divmora.io",
		"first.last@sub.domain.co.uk",
	}
	for _, email := range validEmails {
		c := makeClaims(email)
		if err := c.ValidateClaimsSchema(); err != nil {
			t.Errorf("expected email %q to be valid, got: %v", email, err)
		}
	}

	invalidEmails := []string{
		"not-an-email",
		"user@",
		"@domain.com",
		"user@domain",
		"user@.com",
		"user@domain..com",
		"user name@domain.com",
	}
	for _, email := range invalidEmails {
		c := makeClaims(email)
		err := c.ValidateClaimsSchema()
		if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "customer.email") {
			t.Errorf("expected ErrInvalidLicenseFormat for invalid email %q, got: %v", email, err)
		}
	}
}

func TestValidateClaimsPayloadJSON_LimitsTypeConstraint(t *testing.T) {
	// Valid limits with integer values
	validJSON := []byte(`{
		"id": "550e8400-e29b-41d4-a716-446655440000",
		"customer": {"name": "Acme Corp"},
		"product": "gitlab-fleet-governor",
		"plan": "enterprise",
		"issued_at": "2026-01-01T00:00:00Z",
		"limits": {
			"max_nodes": 10,
			"max_runners": 50,
			"unlimited_val": -1
		}
	}`)
	if err := license.ValidateClaimsPayloadJSON(validJSON); err != nil {
		t.Fatalf("expected valid JSON to pass validation: %v", err)
	}

	// Invalid limits with floating-point value
	floatJSON := []byte(`{
		"id": "550e8400-e29b-41d4-a716-446655440000",
		"customer": {"name": "Acme Corp"},
		"product": "gitlab-fleet-governor",
		"plan": "enterprise",
		"issued_at": "2026-01-01T00:00:00Z",
		"limits": {
			"max_runners": 1.5
		}
	}`)
	err := license.ValidateClaimsPayloadJSON(floatJSON)
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "must be an integer") {
		t.Errorf("expected ErrInvalidLicenseFormat for float limit, got: %v", err)
	}

	// Missing plan in JSON
	missingPlanJSON := []byte(`{
		"id": "550e8400-e29b-41d4-a716-446655440000",
		"customer": {"name": "Acme Corp"},
		"product": "gitlab-fleet-governor",
		"issued_at": "2026-01-01T00:00:00Z"
	}`)
	err = license.ValidateClaimsPayloadJSON(missingPlanJSON)
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) || !strings.Contains(err.Error(), "claims.plan is required") {
		t.Errorf("expected ErrInvalidLicenseFormat for missing plan, got: %v", err)
	}
}

func TestSigner_SchemaValidationFailFast(t *testing.T) {
	_, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signer, err := license.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Invalid email on issuance
	claims := license.Claims{
		Customer: license.Customer{
			Name:  "Acme Corp",
			Email: "invalid-email-address",
		},
		Product: "gitlab-fleet-governor",
	}
	_, err = signer.Sign(claims)
	if err == nil || !errors.Is(err, license.ErrInvalidLicenseFormat) {
		t.Fatalf("expected signer to fail fast on invalid email with ErrInvalidLicenseFormat, got: %v", err)
	}
}
