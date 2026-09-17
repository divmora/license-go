package envelope

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidLicenseFormat is returned when the raw license string cannot be parsed or decoded.
	ErrInvalidLicenseFormat = errors.New("license: invalid license format")

	// ErrLicenseNotFound is returned when no license data is found in the specified source.
	ErrLicenseNotFound = errors.New("license: license not found")
)

const (
	// VersionPrefix is the protocol version identifier.
	VersionPrefix = "DIV1"
)

// EncodeToken creates a compact single-line license token:
// "DIV1.<base64url(payload)>.<base64url(signature)>".
func EncodeToken(payloadJSON []byte, signature []byte) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s.%s", VersionPrefix, payloadB64, sigB64)
}

// ParseToken unpacks a raw or armored license string into its component parts:
// payload JSON bytes, signature bytes, and the canonical signed bytes used for signature verification.
func ParseToken(raw string) (payloadJSON []byte, signature []byte, signedData []byte, err error) {
	token, err := UnwrapToken(raw)
	if err != nil {
		return nil, nil, nil, err
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: expected 3 dot-separated segments, got %d", ErrInvalidLicenseFormat, len(parts))
	}

	version := parts[0]
	if version != VersionPrefix {
		return nil, nil, nil, fmt.Errorf("%w: unsupported token version %q, expected %q", ErrInvalidLicenseFormat, version, VersionPrefix)
	}

	payloadJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fallback to standard Base64 if padded
		payloadJSON, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: invalid payload base64: %v", ErrInvalidLicenseFormat, err)
		}
	}

	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		// Fallback to standard Base64 if padded
		signature, err = base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: invalid signature base64: %v", ErrInvalidLicenseFormat, err)
		}
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, nil, nil, fmt.Errorf("%w: signature length is %d bytes, expected %d", ErrInvalidLicenseFormat, len(signature), ed25519.SignatureSize)
	}

	// Canonical signed data is "DIV1.<base64url(payload)>"
	signedData = []byte(fmt.Sprintf("%s.%s", version, parts[1]))
	return payloadJSON, signature, signedData, nil
}
