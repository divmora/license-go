package license

import (
	"github.com/divmora/license-go/internal/envelope"
)

const (
	// VersionPrefix is the protocol version identifier.
	VersionPrefix = envelope.VersionPrefix

	// ArmoredHeader is the beginning boundary of an armored license block.
	ArmoredHeader = envelope.ArmoredHeader

	// ArmoredFooter is the ending boundary of an armored license block.
	ArmoredFooter = envelope.ArmoredFooter

	// LineWrapLength is the line length used when formatting armored license text.
	LineWrapLength = envelope.LineWrapLength
)

// EncodeToken creates a compact single-line license token:
// "DIV1.<base64url(payload)>.<base64url(signature)>".
func EncodeToken(payloadJSON []byte, signature []byte) string {
	return envelope.EncodeToken(payloadJSON, signature)
}

// EncodeArmored creates a human-readable armored license text block:
//
//	-----BEGIN DIVMORA LICENSE KEY-----
//	<wrapped token>
//	-----END DIVMORA LICENSE KEY-----
func EncodeArmored(payloadJSON []byte, signature []byte) string {
	return envelope.EncodeArmored(payloadJSON, signature)
}

// WrapArmored wraps a raw token string in the standard Divmora armored header and footer,
// breaking long lines every 64 characters.
func WrapArmored(token string) string {
	return envelope.WrapArmored(token)
}

// UnwrapToken extracts the raw token string from either an armored text block
// or a raw compact token, stripping boundary headers, footers, newlines, and whitespaces.
func UnwrapToken(raw string) (string, error) {
	return envelope.UnwrapToken(raw)
}

// ParseToken unpacks a raw or armored license string into its component parts:
// payload JSON bytes, signature bytes, and the canonical signed bytes used for signature verification.
func ParseToken(raw string) (payloadJSON []byte, signature []byte, signedData []byte, err error) {
	return envelope.ParseToken(raw)
}
