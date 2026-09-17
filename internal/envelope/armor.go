package envelope

import (
	"fmt"
	"strings"
)

const (
	// ArmoredHeader is the beginning boundary of an armored license block.
	ArmoredHeader = "-----BEGIN DIVMORA LICENSE KEY-----"

	// ArmoredFooter is the ending boundary of an armored license block.
	ArmoredFooter = "-----END DIVMORA LICENSE KEY-----"

	// LineWrapLength is the line length used when formatting armored license text.
	LineWrapLength = 64
)

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
