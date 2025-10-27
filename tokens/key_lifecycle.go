package tokens

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// KeyStatus represents the lifecycle status of a signing key
type KeyStatus string

const (
	// KeyStatusActive indicates the key is active and can be used for both signing and verification
	KeyStatusActive KeyStatus = "active"
	// KeyStatusDeprecated indicates the key can verify tokens but should not sign new ones
	KeyStatusDeprecated KeyStatus = "deprecated"
	// KeyStatusRevoked indicates the key should not be used for signing or verification
	KeyStatusRevoked KeyStatus = "revoked"
)

// KeyMetadata tracks the lifecycle information for a signing key
type KeyMetadata struct {
	KeyID        string
	Status       KeyStatus
	CreatedAt    time.Time
	DeprecatedAt *time.Time
	RevokedAt    *time.Time
	Algorithm    string
	mu           sync.RWMutex
}

// IsActive returns true if the key is in active status
func (km *KeyMetadata) IsActive() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.Status == KeyStatusActive
}

// IsDeprecated returns true if the key is deprecated
func (km *KeyMetadata) IsDeprecated() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.Status == KeyStatusDeprecated
}

// IsRevoked returns true if the key is revoked
func (km *KeyMetadata) IsRevoked() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.Status == KeyStatusRevoked
}

// Deprecate marks the key as deprecated
func (km *KeyMetadata) Deprecate() {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.Status == KeyStatusActive {
		now := time.Now()
		km.Status = KeyStatusDeprecated
		km.DeprecatedAt = &now
	}
}

// Revoke marks the key as revoked
func (km *KeyMetadata) Revoke() {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.Status != KeyStatusRevoked {
		now := time.Now()
		km.Status = KeyStatusRevoked
		km.RevokedAt = &now
	}
}

// keyLifecycleManager manages key metadata and lifecycle operations
type keyLifecycleManager struct {
	metadata map[string]*KeyMetadata
	mu       sync.RWMutex
}

// newKeyLifecycleManager creates a new key lifecycle manager
func newKeyLifecycleManager() *keyLifecycleManager {
	return &keyLifecycleManager{
		metadata: make(map[string]*KeyMetadata),
	}
}

// AddKey registers a new key with active status
func (klm *keyLifecycleManager) AddKey(kid string, algorithm string) {
	klm.mu.Lock()
	defer klm.mu.Unlock()

	if _, exists := klm.metadata[kid]; !exists {
		klm.metadata[kid] = &KeyMetadata{
			KeyID:     kid,
			Status:    KeyStatusActive,
			CreatedAt: time.Now(),
			Algorithm: algorithm,
		}
	}
}

// GetMetadata returns metadata for a key
func (klm *keyLifecycleManager) GetMetadata(kid string) (*KeyMetadata, bool) {
	klm.mu.RLock()
	defer klm.mu.RUnlock()
	meta, exists := klm.metadata[kid]

	return meta, exists
}

// ListActive returns all active key IDs
func (klm *keyLifecycleManager) ListActive() []string {
	klm.mu.RLock()
	defer klm.mu.RUnlock()

	var active []string

	for kid, meta := range klm.metadata {
		if meta.IsActive() {
			active = append(active, kid)
		}
	}

	return active
}

// ListDeprecated returns all deprecated key IDs
func (klm *keyLifecycleManager) ListDeprecated() []string {
	klm.mu.RLock()
	defer klm.mu.RUnlock()

	var deprecated []string

	for kid, meta := range klm.metadata {
		if meta.IsDeprecated() {
			deprecated = append(deprecated, kid)
		}
	}

	return deprecated
}

// DeprecateKey marks a key as deprecated
func (klm *keyLifecycleManager) DeprecateKey(kid string) bool {
	meta, exists := klm.GetMetadata(kid)
	if !exists {
		return false
	}

	meta.Deprecate()

	return true
}

// RevokeKey marks a key as revoked
func (klm *keyLifecycleManager) RevokeKey(kid string) bool {
	meta, exists := klm.GetMetadata(kid)
	if !exists {
		return false
	}

	meta.Revoke()

	return true
}

// RemoveKey removes key metadata
func (klm *keyLifecycleManager) RemoveKey(kid string) {
	klm.mu.Lock()
	defer klm.mu.Unlock()
	delete(klm.metadata, kid)
}

// RotateKey generates a new key and deprecates the current one
type RotateKeyFunc func() (kid string, signer crypto.Signer, err error)

// KeyRotationConfig defines configuration for key rotation
type KeyRotationConfig struct {
	// RotationInterval is how often to rotate keys
	RotationInterval time.Duration
	// DeprecationGracePeriod is how long to keep old keys as deprecated before revoking
	DeprecationGracePeriod time.Duration
	// GenerateKeyFunc is the function to generate new keys
	GenerateKeyFunc RotateKeyFunc
}

// RotationResult contains the result of a key rotation operation
type RotationResult struct {
	NewKeyID       string
	DeprecatedKeys []string
	RevokedKeys    []string
}

// ShouldRotate checks if rotation is needed based on the current key age
func (tm *TokenManager) ShouldRotate(maxAge time.Duration) bool {
	if tm.keyLifecycle == nil {
		return false
	}

	meta, exists := tm.keyLifecycle.GetMetadata(tm.currentKeyID)
	if !exists {
		return false
	}

	return time.Since(meta.CreatedAt) > maxAge
}

// DeprecateKey marks a signing key as deprecated
func (tm *TokenManager) DeprecateKey(kid string) error {
	if tm.keyLifecycle == nil {
		return ErrKeyLifecycleNotEnabled
	}

	if !tm.keyLifecycle.DeprecateKey(kid) {
		return ErrUnknownSigningKey
	}

	return nil
}

// RevokeKey marks a signing key as revoked and removes it from the key set
func (tm *TokenManager) RevokeKey(kid string) error {
	if tm.keyLifecycle == nil {
		return ErrKeyLifecycleNotEnabled
	}

	if !tm.keyLifecycle.RevokeKey(kid) {
		return ErrUnknownSigningKey
	}

	tm.RemoveSigningKeyByID(kid)
	tm.keyLifecycle.RemoveKey(kid)

	return nil
}

// GetKeyMetadata returns metadata for a key
func (tm *TokenManager) GetKeyMetadata(kid string) (*KeyMetadata, error) {
	if tm.keyLifecycle == nil {
		return nil, ErrKeyLifecycleNotEnabled
	}

	meta, exists := tm.keyLifecycle.GetMetadata(kid)
	if !exists {
		return nil, ErrUnknownSigningKey
	}

	return meta, nil
}

// ListActiveKeys returns all active signing keys
func (tm *TokenManager) ListActiveKeys() []string {
	if tm.keyLifecycle == nil {
		return nil
	}

	return tm.keyLifecycle.ListActive()
}

// ListDeprecatedKeys returns all deprecated signing keys
func (tm *TokenManager) ListDeprecatedKeys() []string {
	if tm.keyLifecycle == nil {
		return nil
	}

	return tm.keyLifecycle.ListDeprecated()
}

// RotateKeys performs key rotation: creates new key, deprecates current, removes old deprecated keys
func (tm *TokenManager) RotateKeys(generateKey RotateKeyFunc, deprecationGrace time.Duration) (*RotationResult, error) {
	if tm.keyLifecycle == nil {
		return nil, ErrKeyLifecycleNotEnabled
	}

	result := &RotationResult{
		DeprecatedKeys: []string{},
		RevokedKeys:    []string{},
	}

	previousKeyID := tm.currentKeyID

	kid, signer, err := generateKey()
	if err != nil {
		return nil, err
	}

	if err := tm.AddSigningKeyWithID(kid, signer); err != nil {
		return nil, err
	}

	result.NewKeyID = kid

	if previousKeyID != "" && previousKeyID != kid {
		if err := tm.DeprecateKey(previousKeyID); err == nil {
			result.DeprecatedKeys = append(result.DeprecatedKeys, previousKeyID)
		}
	}

	cutoff := time.Now().Add(-deprecationGrace)

	for _, deprecatedKID := range tm.ListDeprecatedKeys() {
		if meta, exists := tm.keyLifecycle.GetMetadata(deprecatedKID); exists {
			if meta.DeprecatedAt != nil && meta.DeprecatedAt.Before(cutoff) {
				if err := tm.RevokeKey(deprecatedKID); err == nil {
					result.RevokedKeys = append(result.RevokedKeys, deprecatedKID)
				}
			}
		}
	}

	return result, nil
}

// GenerateEd25519Key is a helper function to generate a new Ed25519 signing key
func GenerateEd25519Key() (kid string, signer crypto.Signer, err error) {
	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return "", nil, genErr
	}

	kid = ulid.Make().String()

	return kid, priv, nil
}
