package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// KeyStatus represents the lifecycle state of a public key in the KeyRing.
type KeyStatus string

const (
	// KeyStatusActive indicates the key is active and trusted for validating signatures.
	KeyStatusActive KeyStatus = "ACTIVE"
	// KeyStatusRetiring indicates the key is being phased out but remains trusted for legacy licenses.
	KeyStatusRetiring KeyStatus = "RETIRING"
	// KeyStatusRevoked indicates the key has been compromised or revoked; any licenses signed by it are rejected.
	KeyStatusRevoked KeyStatus = "REVOKED"
)

// KeyEntry represents a single public key registered in a KeyRing with associated metadata.
type KeyEntry struct {
	ID          string            `json:"id"`
	PublicKey   ed25519.PublicKey `json:"-"`
	Fingerprint string            `json:"fingerprint"`
	Status      KeyStatus         `json:"status"`
	Description string            `json:"description,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// KeyOption is a functional option for configuring a KeyEntry upon addition.
type KeyOption func(*KeyEntry)

// WithKeyStatus sets the initial status of a key entry.
func WithKeyStatus(status KeyStatus) KeyOption {
	return func(e *KeyEntry) {
		e.Status = status
	}
}

// WithKeyDescription sets a human-readable description for the key entry.
func WithKeyDescription(desc string) KeyOption {
	return func(e *KeyEntry) {
		e.Description = desc
	}
}

// WithCustomKeyID sets a custom identifier for the key entry (defaults to its fingerprint).
func WithCustomKeyID(id string) KeyOption {
	return func(e *KeyEntry) {
		if strings.TrimSpace(id) != "" {
			e.ID = strings.TrimSpace(id)
		}
	}
}

// KeyRing holds a collection of trusted Ed25519 public keys for zero-downtime key rotation
// and emergency key revocation. It is safe for concurrent access across multiple goroutines.
type KeyRing struct {
	mu            sync.RWMutex
	primary       *KeyEntry
	keys          []*KeyEntry
	byID          map[string]*KeyEntry
	byFingerprint map[string]*KeyEntry
}

// NewKeyRing initializes a KeyRing with a primary public key and optional fallback keys.
func NewKeyRing(primaryKey ed25519.PublicKey, fallbacks ...ed25519.PublicKey) *KeyRing {
	ring := &KeyRing{
		byID:          make(map[string]*KeyEntry),
		byFingerprint: make(map[string]*KeyEntry),
	}

	if len(primaryKey) == ed25519.PublicKeySize {
		entry := ring.createEntry(primaryKey, KeyStatusActive, "")
		ring.primary = entry
		ring.keys = append(ring.keys, entry)
		ring.indexEntry(entry)
	}

	for _, fb := range fallbacks {
		if len(fb) == ed25519.PublicKeySize {
			entry := ring.createEntry(fb, KeyStatusRetiring, "")
			ring.keys = append(ring.keys, entry)
			ring.indexEntry(entry)
		}
	}

	return ring
}

// NewKeyRingFromPEM creates a KeyRing by parsing all public key blocks in the provided PKIX PEM data.
// The first public key is assigned as Primary; subsequent keys are added as Retiring fallback keys.
func NewKeyRingFromPEM(pemBytes []byte) (*KeyRing, error) {
	keys, err := ParsePublicKeysFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no valid Ed25519 public keys found in PEM data")
	}

	ring := NewKeyRing(keys[0], keys[1:]...)
	return ring, nil
}

// NewKeyRingFromPEMFile loads and parses a multi-key PEM bundle from the specified file path.
func NewKeyRingFromPEMFile(filePath string) (*KeyRing, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public keys bundle file: %w", err)
	}
	return NewKeyRingFromPEM(data)
}

func (r *KeyRing) createEntry(pub ed25519.PublicKey, status KeyStatus, id string) *KeyEntry {
	fp := KeyFingerprint(pub)
	entryID := fp
	if id != "" {
		entryID = id
	}
	return &KeyEntry{
		ID:          entryID,
		PublicKey:   pub,
		Fingerprint: fp,
		Status:      status,
		CreatedAt:   time.Now().UTC(),
	}
}

func (r *KeyRing) indexEntry(entry *KeyEntry) {
	if entry.ID != "" {
		r.byID[entry.ID] = entry
	}
	if entry.Fingerprint != "" {
		r.byFingerprint[entry.Fingerprint] = entry
	}
	if len(entry.PublicKey) == ed25519.PublicKeySize {
		shortFP := KeyFingerprintShort(entry.PublicKey)
		if shortFP != "" {
			r.byFingerprint[shortFP] = entry
		}
	}
}

func (r *KeyRing) findEntryLocked(idOrFingerprint string) (*KeyEntry, bool) {
	if strings.HasPrefix(idOrFingerprint, "sha256:") {
		if entry, ok := r.byFingerprint[idOrFingerprint]; ok {
			return entry, true
		}
	}
	if entry, ok := r.byID[idOrFingerprint]; ok {
		return entry, true
	}
	if entry, ok := r.byFingerprint[idOrFingerprint]; ok {
		return entry, true
	}
	return nil, false
}

// AddKey adds a public key to the KeyRing with configurable options.
func (r *KeyRing) AddKey(pub ed25519.PublicKey, opts ...KeyOption) (*KeyEntry, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrMissingPublicKey
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry := r.createEntry(pub, KeyStatusActive, "")
	for _, opt := range opts {
		opt(entry)
	}

	if r.primary == nil {
		r.primary = entry
	}

	r.keys = append(r.keys, entry)
	r.indexEntry(entry)
	return entry, nil
}

// AddKeyWithID adds a public key with an explicit Key ID and status.
func (r *KeyRing) AddKeyWithID(id string, pub ed25519.PublicKey, status KeyStatus) (*KeyEntry, error) {
	return r.AddKey(pub, WithCustomKeyID(id), WithKeyStatus(status))
}

// SetPrimary designates an existing key (by ID or fingerprint) as the primary active key.
func (r *KeyRing) SetPrimary(idOrFingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.findEntryLocked(idOrFingerprint)
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyNotFound, idOrFingerprint)
	}

	r.primary = entry
	entry.Status = KeyStatusActive
	return nil
}

// Revoke marks a key (by ID or fingerprint) as REVOKED. Any licenses signed by this key will be rejected.
func (r *KeyRing) Revoke(idOrFingerprint string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.findEntryLocked(idOrFingerprint)
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyNotFound, idOrFingerprint)
	}

	entry.Status = KeyStatusRevoked
	return nil
}

// Primary returns the primary active KeyEntry, or nil if the ring is empty.
func (r *KeyRing) Primary() *KeyEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.primary
}

// Keys returns a slice of all registered KeyEntry records in order.
func (r *KeyRing) Keys() []*KeyEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*KeyEntry, len(r.keys))
	copy(result, r.keys)
	return result
}

// FindKey looks up a KeyEntry by its Key ID or SHA-256 fingerprint.
func (r *KeyRing) FindKey(idOrFingerprint string) (*KeyEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.findEntryLocked(idOrFingerprint)
}

// FindKeyByID looks up a KeyEntry specifically by its Key ID.
func (r *KeyRing) FindKeyByID(id string) (*KeyEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.byID[id]
	return entry, ok
}

// FindKeyByFingerprint looks up a KeyEntry specifically by its SHA-256 fingerprint.
func (r *KeyRing) FindKeyByFingerprint(fp string) (*KeyEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.byFingerprint[fp]
	return entry, ok
}

// Count returns the total number of registered keys.
func (r *KeyRing) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keys)
}

// VerifySignature verifies an Ed25519 signature over signedData against the keys in the ring.
//
// If targetKeyID is specified and exists in the ring, that key is evaluated first.
// If trial verification matches a key whose status is REVOKED, ErrKeyRevoked is returned.
// Returns the matched KeyEntry upon success, or ErrInvalidSignature if no key matches.
func (r *KeyRing) VerifySignature(signedData, sig []byte, targetKeyID string) (*KeyEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.keys) == 0 {
		return nil, ErrMissingPublicKey
	}

	// 1. If targetKeyID is specified, check that specific key first
	if targetKeyID != "" {
		if entry, ok := r.findEntryLocked(targetKeyID); ok {
			if ed25519.Verify(entry.PublicKey, signedData, sig) {
				if entry.Status == KeyStatusRevoked {
					return nil, ErrKeyRevoked
				}
				return entry, nil
			}
		}
	}

	// 2. Fast-path: try primary key
	if r.primary != nil {
		if ed25519.Verify(r.primary.PublicKey, signedData, sig) {
			if r.primary.Status == KeyStatusRevoked {
				return nil, ErrKeyRevoked
			}
			return r.primary, nil
		}
	}

	// 3. Fallback: trial verify against all other keys in the ring
	for _, entry := range r.keys {
		if r.primary != nil && entry == r.primary {
			continue
		}
		if ed25519.Verify(entry.PublicKey, signedData, sig) {
			if entry.Status == KeyStatusRevoked {
				return nil, ErrKeyRevoked
			}
			return entry, nil
		}
	}

	return nil, ErrInvalidSignature
}
