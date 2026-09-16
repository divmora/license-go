package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const (
	// PEMTypePrivateKey is the PEM block type for PKCS#8 private keys.
	PEMTypePrivateKey = "PRIVATE KEY"
	// PEMTypePublicKey is the PEM block type for PKIX public keys.
	PEMTypePublicKey = "PUBLIC KEY"
)

// GenerateKeyPair generates a new cryptographically secure Ed25519 public and private key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// EncodePrivateKeyToPEM marshals an Ed25519 private key into PKCS#8 PEM format.
func EncodePrivateKeyToPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) == 0 {
		return nil, ErrMissingPrivateKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// EncodePublicKeyToPEM marshals an Ed25519 public key into PKIX PEM format.
func EncodePublicKeyToPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) == 0 {
		return nil, ErrMissingPublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to PKIX: %w", err)
	}
	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePrivateKeyFromPEM parses a PKCS#8 PEM-encoded Ed25519 private key.
func ParsePrivateKeyFromPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T, expected Ed25519", key)
	}
	return privKey, nil
}

// ParsePublicKeyFromPEM parses a PKIX PEM-encoded Ed25519 public key.
func ParsePublicKeyFromPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	pubKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T, expected Ed25519", key)
	}
	return pubKey, nil
}

// EncodePublicKeyToBase64 encodes raw Ed25519 public key bytes as standard base64.
func EncodePublicKeyToBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKeyFromBase64 parses a raw 32-byte Ed25519 public key from base64,
// or falls back to PKIX DER base64 decoding.
func ParsePublicKeyFromBase64(s string) (ed25519.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 public key: %w", err)
		}
	}

	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}

	// Try parsing as PKIX DER
	key, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		if pubKey, ok := key.(ed25519.PublicKey); ok {
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("invalid Ed25519 public key data length: %d bytes (expected %d)", len(data), ed25519.PublicKeySize)
}

// SavePrivateKeyToPEMFile writes an Ed25519 private key to a PEM file with the specified file permissions.
func SavePrivateKeyToPEMFile(priv ed25519.PrivateKey, filePath string, perm os.FileMode) error {
	pemData, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, pemData, perm)
}

// SavePublicKeyToPEMFile writes an Ed25519 public key to a PEM file.
func SavePublicKeyToPEMFile(pub ed25519.PublicKey, filePath string, perm os.FileMode) error {
	pemData, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, pemData, perm)
}

// LoadPrivateKeyFromPEMFile reads and parses an Ed25519 private key from a PEM file.
func LoadPrivateKeyFromPEMFile(filePath string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return ParsePrivateKeyFromPEM(data)
}

// LoadPublicKeyFromPEMFile reads and parses an Ed25519 public key from a PEM file.
func LoadPublicKeyFromPEMFile(filePath string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	return ParsePublicKeyFromPEM(data)
}
