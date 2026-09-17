package schema

import (
	"encoding/json"
	"fmt"

	"github.com/divmora/license-go/internal/envelope"
	"github.com/divmora/license-go/internal/helpers"
)

// ValidateClaimsPayloadJSON validates raw JSON claims bytes against the DIV1 JSON schema constraints
// specified in SPEC.md §4.1.
// Validates required fields, object structures, email format, and limit integer type constraints.
// Returns a typed error wrapping envelope.ErrInvalidLicenseFormat on violation.
func ValidateClaimsPayloadJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: failed to parse claims JSON: %v", envelope.ErrInvalidLicenseFormat, err)
	}

	requiredFields := []string{"id", "customer", "product", "plan", "issued_at"}
	for _, req := range requiredFields {
		rawVal, exists := raw[req]
		if !exists || len(rawVal) == 0 || string(rawVal) == "null" || string(rawVal) == `""` {
			return fmt.Errorf("%w: claims.%s is required", envelope.ErrInvalidLicenseFormat, req)
		}
	}

	// Validate customer object
	var custRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw["customer"], &custRaw); err != nil {
		return fmt.Errorf("%w: claims.customer must be an object: %v", envelope.ErrInvalidLicenseFormat, err)
	}
	if nameRaw, ok := custRaw["name"]; !ok || len(nameRaw) == 0 || string(nameRaw) == "null" || string(nameRaw) == `""` {
		return fmt.Errorf("%w: claims.customer.name is required", envelope.ErrInvalidLicenseFormat)
	}

	// Validate customer.email format if provided
	if emailRaw, ok := custRaw["email"]; ok && len(emailRaw) > 0 && string(emailRaw) != "null" {
		var emailStr string
		if err := json.Unmarshal(emailRaw, &emailStr); err == nil && emailStr != "" {
			if !helpers.IsValidEmail(emailStr) {
				return fmt.Errorf("%w: claims.customer.email format is invalid: %q", envelope.ErrInvalidLicenseFormat, emailStr)
			}
		}
	}

	// Validate limits types (must be integers, reject floats like 1.5)
	if limitsRaw, ok := raw["limits"]; ok && len(limitsRaw) > 0 && string(limitsRaw) != "null" {
		var limMap map[string]interface{}
		if err := json.Unmarshal(limitsRaw, &limMap); err != nil {
			return fmt.Errorf("%w: claims.limits must be a map of integer values: %v", envelope.ErrInvalidLicenseFormat, err)
		}
		for k, val := range limMap {
			switch v := val.(type) {
			case float64:
				if v != float64(int64(v)) {
					return fmt.Errorf("%w: claims.limits[%q] must be an integer, got float %v", envelope.ErrInvalidLicenseFormat, k, v)
				}
			default:
				return fmt.Errorf("%w: claims.limits[%q] must be an integer", envelope.ErrInvalidLicenseFormat, k)
			}
		}
	}

	return nil
}
