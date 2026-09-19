package license

import (
	"crypto/ed25519"
	"encoding/base64"
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
	// ProtocolPrefixCRL is the wire format protocol prefix for Divmora Revocation Lists.
	ProtocolPrefixCRL = "DIVCRL1"

	// PEMTypeRevocationList is the PEM block type for armored revocation lists.
	PEMTypeRevocationList = "DIVMORA REVOCATION LIST"
)

// RevocationEntry represents a single invalidated license record within a CRL.
type RevocationEntry struct {
	// ID is the unique identifier (e.g. UUID) of the revoked license.
	ID string `json:"id"`

	// RevokedAt is the timestamp when the license was officially revoked.
	RevokedAt time.Time `json:"revoked_at"`

	// Reason describes the cause of revocation (e.g., "compromised", "refunded", "superseded", "payment_failed").
	Reason string `json:"reason,omitempty"`
}

// RevocationListClaims contains the authenticated payload of a signed Certificate Revocation List (CRL).
type RevocationListClaims struct {
	// ID is the unique identifier for this CRL issuance.
	ID string `json:"id"`

	// Issuer identifies the issuing organization or licensing authority (e.g. "divmora.com/crl").
	Issuer string `json:"issuer,omitempty"`

	// Product restricts this CRL to a specific product, or empty/"*" for organization-wide applicability.
	Product string `json:"product,omitempty"`

	// KeyID identifies the signing key used to authenticate this revocation list.
	KeyID string `json:"kid,omitempty"`

	// IssuedAt indicates when this CRL was minted.
	IssuedAt time.Time `json:"issued_at"`

	// NextUpdate specifies the cutoff timestamp after which this CRL should be considered stale/expired.
	// A zero time indicates a perpetual/unexpiring revocation list.
	NextUpdate time.Time `json:"next_update,omitempty"`

	// Entries lists all invalidated licenses.
	Entries []RevocationEntry `json:"entries"`

	// Metadata holds arbitrary key-value pairs for audit trails or operational context.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate asserts that required fields in the revocation list are populated and well-formed.
func (c *RevocationListClaims) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("license: revocation list missing required 'id'")
	}
	if c.IssuedAt.IsZero() {
		return errors.New("license: revocation list missing required 'issued_at'")
	}
	return nil
}

// Count returns the total number of revoked licenses in this list.
func (c *RevocationListClaims) Count() int {
	if c == nil {
		return 0
	}
	return len(c.Entries)
}

// IsRevoked checks whether a given license ID is listed in this CRL.
// Matching is case-insensitive and trims surrounding whitespace.
func (c *RevocationListClaims) IsRevoked(licenseID string) (*RevocationEntry, bool) {
	if c == nil || len(c.Entries) == 0 {
		return nil, false
	}
	target := strings.ToLower(strings.TrimSpace(licenseID))
	if target == "" {
		return nil, false
	}
	for i := range c.Entries {
		if strings.ToLower(strings.TrimSpace(c.Entries[i].ID)) == target {
			return &c.Entries[i], true
		}
	}
	return nil, false
}

// IsExpiredAt reports whether this CRL has passed its NextUpdate expiration cutoff relative to reference time `now`.
func (c *RevocationListClaims) IsExpiredAt(now time.Time) bool {
	if c == nil || c.NextUpdate.IsZero() {
		return false
	}
	return now.After(c.NextUpdate)
}

// FormatInspect returns a formatted, multi-line summary of the CRL claims for terminal inspection.
func (c *RevocationListClaims) FormatInspect() string {
	if c == nil {
		return "No revocation list claims to inspect\n"
	}

	var b strings.Builder
	headerDivider := strings.Repeat("=", 80)

	b.WriteString(headerDivider + "\n")
	b.WriteString("DIVMORA CERTIFICATE REVOCATION LIST (CRL)\n")
	b.WriteString(headerDivider + "\n")

	fmt.Fprintf(&b, "%-24s %s\n", "CRL ID:", c.ID)
	if c.Issuer != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Issuer:", c.Issuer)
	}
	if c.Product != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Product Scope:", c.Product)
	}
	if c.KeyID != "" {
		fmt.Fprintf(&b, "%-24s %s\n", "Signing Key ID:", c.KeyID)
	}
	if !c.IssuedAt.IsZero() {
		fmt.Fprintf(&b, "%-24s %s\n", "Issued At:", c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !c.NextUpdate.IsZero() {
		fmt.Fprintf(&b, "%-24s %s\n", "Next Update:", c.NextUpdate.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "%-24s %d\n", "Revoked Licenses:", len(c.Entries))

	if len(c.Metadata) > 0 {
		b.WriteString("\nMETADATA\n")
		keys := make([]string, 0, len(c.Metadata))
		for k := range c.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  • %-22s %s\n", k+":", c.Metadata[k])
		}
	}

	if len(c.Entries) > 0 {
		b.WriteString("\nREVOKED ENTRIES\n")
		fmt.Fprintf(&b, "  %-38s %-24s %s\n", "LICENSE ID", "REVOKED AT", "REASON")
		fmt.Fprintf(&b, "  %-38s %-24s %s\n", strings.Repeat("-", 38), strings.Repeat("-", 24), strings.Repeat("-", 14))
		for _, entry := range c.Entries {
			dateStr := "N/A"
			if !entry.RevokedAt.IsZero() {
				dateStr = entry.RevokedAt.UTC().Format(time.RFC3339)
			}
			reason := entry.Reason
			if reason == "" {
				reason = "unspecified"
			}
			fmt.Fprintf(&b, "  %-38s %-24s %s\n", entry.ID, dateStr, reason)
		}
	}

	b.WriteString(headerDivider + "\n")
	return b.String()
}

// SignCRLOption configures optional parameters when cryptographically signing a CRL.
type SignCRLOption func(*signCRLConfig)

type signCRLConfig struct {
	keyID string
}

// WithCRLSignerKeyID specifies the Key ID hint to embed in the signed CRL payload.
func WithCRLSignerKeyID(keyID string) SignCRLOption {
	return func(c *signCRLConfig) {
		c.keyID = keyID
	}
}

// SignCRL serializes and cryptographically signs RevocationListClaims using an Ed25519 private key.
// Returns a compact DIVCRL1 token string ("DIVCRL1.<payloadB64>.<sigB64>").
func SignCRL(claims RevocationListClaims, privKey ed25519.PrivateKey, opts ...SignCRLOption) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", ErrMissingPrivateKey
	}

	cfg := signCRLConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.keyID != "" {
		claims.KeyID = cfg.keyID
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	}

	if err := claims.Validate(); err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal revocation list payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	canonicalData := []byte(fmt.Sprintf("%s.%s", ProtocolPrefixCRL, payloadB64))

	sig := ed25519.Sign(privKey, canonicalData)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", ProtocolPrefixCRL, payloadB64, sigB64), nil
}

// SignCRLArmored serializes and cryptographically signs a CRL, returning a PEM-armored text block.
func SignCRLArmored(claims RevocationListClaims, privKey ed25519.PrivateKey, opts ...SignCRLOption) (string, error) {
	token, err := SignCRL(claims, privKey, opts...)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  PEMTypeRevocationList,
		Bytes: []byte(token),
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseCRLToken unpacks a raw compact or armored PEM CRL string into component parts:
// payload JSON bytes, signature bytes, and canonical signed bytes.
func ParseCRLToken(rawToken string) (payloadJSON, sig, signedData []byte, err error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, nil, nil, fmt.Errorf("%w: empty revocation list", ErrInvalidCRL)
	}

	// 1. Decode armored PEM block if present
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, nil, nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidCRL)
		}
		if block.Type != PEMTypeRevocationList {
			return nil, nil, nil, fmt.Errorf("%w: unexpected PEM block type %q, expected %q",
				ErrInvalidCRL, block.Type, PEMTypeRevocationList)
		}
		trimmed = strings.TrimSpace(string(block.Bytes))
	}

	// 2. Compact format: DIVCRL1.<payloadB64>.<sigB64>
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: expected 3 dot-separated segments, got %d",
			ErrInvalidCRL, len(parts))
	}

	if parts[0] != ProtocolPrefixCRL {
		return nil, nil, nil, fmt.Errorf("%w: invalid protocol prefix %q, expected %q",
			ErrInvalidCRL, parts[0], ProtocolPrefixCRL)
	}

	payloadJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed to decode base64 payload: %v",
			ErrInvalidCRL, err)
	}

	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed to decode base64 signature: %v",
			ErrInvalidCRL, err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, nil, nil, fmt.Errorf("%w: signature length is %d bytes, expected %d",
			ErrInvalidCRL, len(sig), ed25519.SignatureSize)
	}

	signedData = []byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	return payloadJSON, sig, signedData, nil
}

// VerifyCRL verifies a CRL token or armored block against a trusted KeyRing.
// Returns verified RevocationListClaims and the verifying KeyEntry.
func VerifyCRL(rawCRL string, ring *KeyRing) (*RevocationListClaims, *KeyEntry, error) {
	if ring == nil || ring.Count() == 0 {
		return nil, nil, ErrMissingPublicKey
	}

	payloadJSON, sig, signedData, err := ParseCRLToken(rawCRL)
	if err != nil {
		return nil, nil, err
	}

	var kidHint string
	var peek struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadJSON, &peek); err == nil {
		kidHint = peek.KeyID
	}

	matchedKey, err := ring.VerifySignature(signedData, sig, kidHint)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCRL, err)
	}

	var claims RevocationListClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse revocation list json: %v", ErrInvalidCRL, err)
	}

	if err := claims.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCRL, err)
	}

	return &claims, matchedKey, nil
}

// InspectCRL decodes and inspects RevocationListClaims from a raw or armored token without signature verification.
func InspectCRL(rawCRL string) (*RevocationListClaims, error) {
	payloadJSON, _, _, err := ParseCRLToken(rawCRL)
	if err != nil {
		return nil, err
	}

	var claims RevocationListClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse revocation list json: %v", ErrInvalidCRL, err)
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCRL, err)
	}

	return &claims, nil
}

// InspectCRLFromFile reads a CRL file from disk and parses claims without signature verification.
func InspectCRLFromFile(filePath string) (*RevocationListClaims, error) {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat crl file %s: %w", filePath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: crl file %s is a symlink", ErrSymlinkNotAllowed, filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read crl file %s: %w", filePath, err)
	}
	return InspectCRL(string(data))
}
