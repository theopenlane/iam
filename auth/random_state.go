package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const defaultOAuthStateEntropyBytes = 32

// GenerateOAuthState returns a URL-safe, cryptographically random OAuth state value.
func GenerateOAuthState(entropyBytes int) (string, error) {
	if entropyBytes <= 0 {
		entropyBytes = defaultOAuthStateEntropyBytes
	}

	buf := make([]byte, entropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRandomStateGeneration, err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
