package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// SignerOption is a functional option for configuring a Signer.
type SignerOption func(*Signer)

// WithSignerKeyID configures the default Key ID to embed in signed license claims.
func WithSignerKeyID(kid string) SignerOption {
	return func(s *Signer) {
		s.keyID = kid
	}
}

// Signer signs license claims using an Ed25519 private key.
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// NewSigner creates a new Signer with the provided Ed25519 private key and options.
func NewSigner(privateKey ed25519.PrivateKey, opts ...SignerOption) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrMissingPrivateKey
	}
	s := &Signer{privateKey: privateKey}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// WithKeyID returns a copy of the Signer configured with the given Key ID.
func (s *Signer) WithKeyID(kid string) *Signer {
	return &Signer{
		privateKey: s.privateKey,
		keyID:      kid,
	}
}

// NewSignerFromPEM creates a new Signer from PKCS#8 PEM-encoded private key bytes.
func NewSignerFromPEM(pemBytes []byte, opts ...SignerOption) (*Signer, error) {
	privKey, err := ParsePrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewSigner(privKey, opts...)
}

// NewSignerFromPEMFile creates a new Signer by loading an Ed25519 private key from a file.
func NewSignerFromPEMFile(filePath string, opts ...SignerOption) (*Signer, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	return NewSignerFromPEM(data, opts...)
}

// Sign marshals and signs the given Claims, returning a compact token string.
// If claims.ID is empty, a random unique ID is generated.
// If claims.KeyID is empty and the signer is configured with a Key ID, it is automatically set.
// If claims.IssuedAt is zero, it defaults to the current UTC time.
func (s *Signer) Sign(claims Claims) (string, error) {
	if s.privateKey == nil {
		return "", ErrMissingPrivateKey
	}

	if claims.Customer.Name == "" {
		return "", errors.New("license: customer name cannot be empty")
	}
	if claims.Product == "" {
		return "", errors.New("license: product cannot be empty")
	}

	// Default ID if not provided
	if claims.ID == "" {
		id, err := generateRandomID()
		if err != nil {
			return "", err
		}
		claims.ID = id
	}

	// Default KeyID if configured on signer
	if claims.KeyID == "" && s.keyID != "" {
		claims.KeyID = s.keyID
	}

	// Default IssuedAt if not provided
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = time.Now().UTC()
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal license claims: %w", err)
	}

	// Construct token and sign canonical data
	// The signed data is "DIV1.<base64url(payloadJSON)>"
	tempToken := EncodeToken(payloadJSON, nil)
	// tempToken is "DIV1.<payloadB64>."
	dotIdx := len(tempToken) - 1
	signedData := []byte(tempToken[:dotIdx])

	sig := ed25519.Sign(s.privateKey, signedData)
	return EncodeToken(payloadJSON, sig), nil
}

// SignArmored marshals and signs Claims, returning an armored text block.
func (s *Signer) SignArmored(claims Claims) (string, error) {
	token, err := s.Sign(claims)
	if err != nil {
		return "", err
	}
	return WrapArmored(token), nil
}

// SignToFile marshals and signs Claims, saving the result to a specified file.
func (s *Signer) SignToFile(claims Claims, filePath string, armored bool) error {
	var content string
	var err error
	if armored {
		content, err = s.SignArmored(claims)
	} else {
		content, err = s.Sign(claims)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(content), 0644)
}

// generateRandomID produces a secure 16-byte random hex string.
func generateRandomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random license ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
