package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
)

// GenerateKeyPair generates a new cryptographically secure Ed25519 public and private key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// SavePrivateKeyToPEMFile writes an Ed25519 private key to a PEM file with the specified file permissions.
func SavePrivateKeyToPEMFile(priv ed25519.PrivateKey, filePath string, perm os.FileMode) error {
	pemData, err := EncodePrivateKeyToPEM(priv)
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
