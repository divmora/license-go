package schema

import (
	"errors"
	"testing"

	"github.com/divmora/license-go/internal/envelope"
)

func TestValidateClaimsPayloadJSON_Valid(t *testing.T) {
	validJSON := []byte(`{
		"id": "lic_123",
		"customer": {"name": "Acme Corp", "email": "admin@acme.com"},
		"product": "gitlab-fleet-governor",
		"plan": "enterprise",
		"issued_at": "2026-01-01T00:00:00Z",
		"limits": {"nodes": 100, "unlimited": -1}
	}`)

	if err := ValidateClaimsPayloadJSON(validJSON); err != nil {
		t.Fatalf("expected valid JSON to pass, got: %v", err)
	}
}

func TestValidateClaimsPayloadJSON_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"missing_id", `{"customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"missing_customer", `{"id":"1","product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"empty_customer_name", `{"id":"1","customer":{"name":""},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"missing_product", `{"id":"1","customer":{"name":"Acme"},"plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"missing_plan", `{"id":"1","customer":{"name":"Acme"},"product":"p","issued_at":"2026-01-01T00:00:00Z"}`},
		{"missing_issued_at", `{"id":"1","customer":{"name":"Acme"},"product":"p","plan":"standard"}`},
		{"invalid_email", `{"id":"1","customer":{"name":"Acme","email":"not-an-email"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"float_limits", `{"id":"1","customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z","limits":{"val":1.5}}`},
		{"string_limits_val", `{"id":"1","customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z","limits":{"val":"text"}}`},
		{"non_object_limits", `{"id":"1","customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z","limits":"not-a-map"}`},
		{"non_object_customer", `{"id":"1","customer":"not-a-map","product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"invalid_json", `{"id":`},
		{"null_id", `{"id":null,"customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
		{"empty_id", `{"id":"","customer":{"name":"Acme"},"product":"p","plan":"standard","issued_at":"2026-01-01T00:00:00Z"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClaimsPayloadJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, envelope.ErrInvalidLicenseFormat) {
				t.Fatalf("expected ErrInvalidLicenseFormat for %s, got: %v", tc.name, err)
			}
		})
	}
}

func TestValidateClaimsPayloadJSON_OptionalFieldsValid(t *testing.T) {
	// null email, null limits
	jsonBytes := []byte(`{
		"id": "lic_1",
		"customer": {"name": "Acme", "email": null},
		"product": "p",
		"plan": "s",
		"issued_at": "2026-01-01T00:00:00Z",
		"limits": null
	}`)
	if err := ValidateClaimsPayloadJSON(jsonBytes); err != nil {
		t.Fatalf("expected valid JSON with null optional fields to pass, got: %v", err)
	}
}
