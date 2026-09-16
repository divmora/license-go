package license

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// PEMTypeLicenseRequest is the PEM block type for armored license requests.
	PEMTypeLicenseRequest = "DIVMORA LICENSE REQUEST"

	// LicenseRequestCurrentVersion is the default version for license request payloads.
	LicenseRequestCurrentVersion = "1"
)

// LicenseRequest encapsulates an air-gapped customer's machine identity and desired licensing parameters.
type LicenseRequest struct {
	// Version is the schema version of the request (default: "1").
	Version string `json:"version"`

	// Customer is the licensee organization or customer name.
	Customer string `json:"customer"`

	// Product is the software product name (e.g. "gitlab-fleet-governor").
	Product string `json:"product"`

	// Plan is the requested license tier (e.g. "enterprise", "pro").
	Plan string `json:"plan,omitempty"`

	// Fingerprint contains the resolved machine or cluster hardware identity.
	Fingerprint MachineFingerprint `json:"fingerprint"`

	// RequestedLimits contains desired capacity limits (e.g. {"runners": 500}).
	RequestedLimits map[string]int64 `json:"requested_limits,omitempty"`

	// RequestedFeatures contains requested feature flags (e.g. ["sso", "audit-logs"]).
	RequestedFeatures []string `json:"requested_features,omitempty"`

	// Notes contains administrative context or deployment instructions.
	Notes string `json:"notes,omitempty"`

	// RequestedAt records when the request was generated.
	RequestedAt time.Time `json:"requested_at"`
}

// NewLicenseRequest creates a new LicenseRequest initialized with current UTC timestamp.
func NewLicenseRequest(customer, product string, fp MachineFingerprint) *LicenseRequest {
	return &LicenseRequest{
		Version:     LicenseRequestCurrentVersion,
		Customer:    strings.TrimSpace(customer),
		Product:     strings.TrimSpace(product),
		Fingerprint: fp,
		RequestedAt: time.Now().UTC(),
	}
}

// Validate asserts that the essential request fields are present and valid.
func (r *LicenseRequest) Validate() error {
	if r == nil {
		return errors.New("license: request is nil")
	}
	if strings.TrimSpace(r.Customer) == "" {
		return errors.New("license: request missing required 'customer'")
	}
	if strings.TrimSpace(r.Product) == "" {
		return errors.New("license: request missing required 'product'")
	}
	if strings.TrimSpace(r.Fingerprint.Primary) == "" && strings.TrimSpace(r.Fingerprint.CanonicalDigest) == "" {
		return errors.New("license: request missing target machine fingerprint")
	}
	return nil
}

// Armored serializes the LicenseRequest into an armored PEM block.
func (r *LicenseRequest) Armored() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode license request JSON: %w", err)
	}

	block := &pem.Block{
		Type:  PEMTypeLicenseRequest,
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil
}

// FormatCard renders a human-readable terminal inspection card for the license request.
func (r *LicenseRequest) FormatCard() string {
	if r == nil {
		return "No license request"
	}

	headerDivider := strings.Repeat("=", 80)
	sectionDivider := strings.Repeat("-", 80)

	var b strings.Builder
	b.WriteString(headerDivider + "\n")
	b.WriteString("                    DIVMORA AIR-GAPPED LICENSE REQUEST\n")
	b.WriteString(headerDivider + "\n")
	fmt.Fprintf(&b, "  %-20s %s\n", "Customer:", r.Customer)
	fmt.Fprintf(&b, "  %-20s %s\n", "Product:", r.Product)
	if r.Plan != "" {
		fmt.Fprintf(&b, "  %-20s %s\n", "Requested Plan:", r.Plan)
	}
	if !r.RequestedAt.IsZero() {
		fmt.Fprintf(&b, "  %-20s %s\n", "Requested At:", r.RequestedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if r.Notes != "" {
		fmt.Fprintf(&b, "  %-20s %s\n", "Notes:", r.Notes)
	}

	b.WriteString(sectionDivider + "\n")
	b.WriteString("TARGET MACHINE IDENTITY\n")
	fmt.Fprintf(&b, "  • %-18s %s\n", "Platform:", r.Fingerprint.Platform)
	fmt.Fprintf(&b, "  • %-18s %s\n", "Primary ID:", r.Fingerprint.Primary)
	if r.Fingerprint.CanonicalDigest != "" {
		fmt.Fprintf(&b, "  • %-18s %s\n", "Digest:", r.Fingerprint.CanonicalDigest)
	}

	if len(r.Fingerprint.Components) > 0 {
		var compKeys []string
		for k := range r.Fingerprint.Components {
			compKeys = append(compKeys, k)
		}
		sort.Strings(compKeys)
		for _, k := range compKeys {
			v := r.Fingerprint.Components[k]
			if v != "" {
				fmt.Fprintf(&b, "  • %-18s %s\n", k+":", v)
			}
		}
	}

	if len(r.RequestedLimits) > 0 || len(r.RequestedFeatures) > 0 {
		b.WriteString(sectionDivider + "\n")
		b.WriteString("REQUESTED ENTITLEMENTS\n")
		if len(r.RequestedLimits) > 0 {
			b.WriteString("  Limits:\n")
			var limitKeys []string
			for k := range r.RequestedLimits {
				limitKeys = append(limitKeys, k)
			}
			sort.Strings(limitKeys)
			for _, k := range limitKeys {
				fmt.Fprintf(&b, "    • %-16s %d\n", k+":", r.RequestedLimits[k])
			}
		}
		if len(r.RequestedFeatures) > 0 {
			b.WriteString("  Features:\n")
			for _, f := range r.RequestedFeatures {
				fmt.Fprintf(&b, "    • %s\n", f)
			}
		}
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

// ParseLicenseRequest decodes a LicenseRequest from raw JSON or an armored PEM block.
func ParseLicenseRequest(data []byte) (*LicenseRequest, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("license: empty license request input")
	}

	// Check if input is PEM-encoded
	if strings.Contains(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("license: failed to decode PEM block in license request")
		}
		if block.Type != PEMTypeLicenseRequest {
			return nil, fmt.Errorf("license: unexpected PEM block type %q, expected %q", block.Type, PEMTypeLicenseRequest)
		}
		data = block.Bytes
	}

	var req LicenseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("license: failed to unmarshal license request JSON: %w", err)
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	return &req, nil
}

// ParseLicenseRequestFile reads and parses a license request from a file path.
func ParseLicenseRequestFile(filePath string) (*LicenseRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("license: failed to read license request file %s: %w", filePath, err)
	}
	return ParseLicenseRequest(data)
}
