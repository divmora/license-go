package license

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// VersionPrefix is the protocol version identifier.
	VersionPrefix = "DIV1"

	// ArmoredHeader is the beginning boundary of an armored license block.
	ArmoredHeader = "-----BEGIN DIVMORA LICENSE KEY-----"

	// ArmoredFooter is the ending boundary of an armored license block.
	ArmoredFooter = "-----END DIVMORA LICENSE KEY-----"

	// LineWrapLength is the line length used when formatting armored license text.
	LineWrapLength = 64
)

// EncodeToken creates a compact single-line license token:
// "DIV1.<base64url(payload)>.<base64url(signature)>".
func EncodeToken(payloadJSON []byte, signature []byte) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s.%s", VersionPrefix, payloadB64, sigB64)
}

// EncodeArmored creates a human-readable armored license text block:
//
//	-----BEGIN DIVMORA LICENSE KEY-----
//	<wrapped token>
//	-----END DIVMORA LICENSE KEY-----
func EncodeArmored(payloadJSON []byte, signature []byte) string {
	token := EncodeToken(payloadJSON, signature)
	return WrapArmored(token)
}

// WrapArmored wraps a raw token string in the standard Divmora armored header and footer,
// breaking long lines every 64 characters.
func WrapArmored(token string) string {
	var builder strings.Builder
	builder.WriteString(ArmoredHeader)
	builder.WriteString("\n")

	for len(token) > LineWrapLength {
		builder.WriteString(token[:LineWrapLength])
		builder.WriteString("\n")
		token = token[LineWrapLength:]
	}
	if len(token) > 0 {
		builder.WriteString(token)
		builder.WriteString("\n")
	}

	builder.WriteString(ArmoredFooter)
	builder.WriteString("\n")
	return builder.String()
}

// UnwrapToken extracts the raw token string from either an armored text block
// or a raw compact token, stripping boundary headers, footers, newlines, and whitespaces.
func UnwrapToken(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrLicenseNotFound
	}

	hasHeader := strings.Contains(trimmed, ArmoredHeader)
	hasFooter := strings.Contains(trimmed, ArmoredFooter)

	if hasHeader && hasFooter {
		startIndex := strings.Index(trimmed, ArmoredHeader) + len(ArmoredHeader)
		endIndex := strings.Index(trimmed, ArmoredFooter)
		if startIndex >= endIndex {
			return "", fmt.Errorf("%w: malformed armored license markers", ErrInvalidLicenseFormat)
		}
		inner := trimmed[startIndex:endIndex]
		// Remove all spaces, tabs, and newlines
		inner = strings.ReplaceAll(inner, "\r", "")
		inner = strings.ReplaceAll(inner, "\n", "")
		inner = strings.ReplaceAll(inner, " ", "")
		inner = strings.ReplaceAll(inner, "\t", "")
		if inner == "" {
			return "", fmt.Errorf("%w: empty armored license payload", ErrInvalidLicenseFormat)
		}
		return inner, nil
	} else if hasHeader || hasFooter {
		return "", fmt.Errorf("%w: incomplete armored license boundary markers", ErrInvalidLicenseFormat)
	}

	// Not armored; clean inline whitespace / carriage returns
	cleaned := strings.ReplaceAll(trimmed, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	return cleaned, nil
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

	// Canonical signed data is "DIV1.<base64url(payload)>"
	signedData = []byte(fmt.Sprintf("%s.%s", version, parts[1]))
	return payloadJSON, signature, signedData, nil
}
