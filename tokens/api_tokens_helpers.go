package tokens

// validateKeyMaterial ensures the provided key contains the minimum required fields
func validateKeyMaterial(key APITokenKey) error {
	if key.Version == "" {
		return ErrAPITokenMissingKeyVersion
	}

	if len(key.Secret) == 0 {
		return ErrAPITokenSecretMissing
	}

	return nil
}

// initialKeyStatus determines the status for a key when constructing a new keyring
func initialKeyStatus(status KeyStatus, assignActive bool) KeyStatus {
	if status != "" {
		return status
	}

	if assignActive {
		return KeyStatusActive
	}

	return KeyStatusDeprecated
}

// upsertKeyStatus determines the status for a key during an upsert operation
func upsertKeyStatus(status KeyStatus) KeyStatus {
	if status != "" {
		return status
	}

	return KeyStatusDeprecated
}

// cloneSecretBytes returns a defensive copy of the provided secret
func cloneSecretBytes(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}

	cloned := make([]byte, len(secret))
	copy(cloned, secret)

	return cloned
}

// ensureSingleActiveKey verifies that exactly one active key exists when building a new keyring
func ensureSingleActiveKey(count int) error {
	if count == 0 {
		return ErrAPITokenNoActiveKey
	}

	if count > 1 {
		return ErrAPITokenMultipleActiveKeys
	}

	return nil
}

// clone creates a deep copy of the API token key to prevent external mutation of stored key material
func (k *APITokenKey) clone() *APITokenKey {
	if k == nil {
		return nil
	}

	cloned := &APITokenKey{
		Version: k.Version,
		Status:  k.Status,
	}

	if len(k.Secret) > 0 {
		cloned.Secret = make([]byte, len(k.Secret))
		copy(cloned.Secret, k.Secret)
	}

	return cloned
}
