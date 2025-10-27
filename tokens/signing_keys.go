package tokens

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const (
	minRSAKeySize = 2048
)

var (
	errUnsupportedKeyType = errors.New("unsupported key type: must be RSA or Ed25519")
	errUnexpectedPEMBlock = errors.New("unexpected PEM block type")
	errMissingPrivateKey  = errors.New("missing private key")
	errPublicKeyMismatch  = errors.New("public key mismatch")
	errRSAKeyTooSmall     = errors.New("RSA key must be at least 2048 bits")
)

// signerLoader defines the interface for loading cryptographic signers from filesystem paths.
type signerLoader interface {
	Load(source string) (crypto.Signer, error)
}

// defaultSignerLoader is a stateless implementation of signerLoader that loads cryptographic signers
// (RSA or Ed25519) from filesystem paths; purpose of this struct is to allow  the token manager to remain
// decoupled from specific loading implementations
type defaultSignerLoader struct{}

// Load loads a cryptographic signer (RSA or Ed25519) from a PEM-encoded file at the specified path
// The loader automatically detects the key type and validates it meets security requirements
// (RSA keys must be at least 2048 bits)
func (defaultSignerLoader) Load(source string) (crypto.Signer, error) {
	return loadSignerFromFile(source)
}

// loadSignerFromFile reads and parses a PEM-encoded private key (RSA or Ed25519) from the specified file path.
// The function automatically detects the key type and performs appropriate validation:
// - RSA keys must be at least 2048 bits
// - Ed25519 keys are validated for correct size
// - Public keys, if present, are validated against the derived public key
func loadSignerFromFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key from %s: %w", path, err)
	}

	var privateKey crypto.Signer

	var publicKey crypto.PublicKey

	for {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "PRIVATE KEY":
			// PKCS#8 format - can be RSA or Ed25519
			key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key in %s: %w", path, parseErr)
			}

			switch typedKey := key.(type) {
			case ed25519.PrivateKey:
				privateKey = typedKey
			case *rsa.PrivateKey:
				// Validate RSA key size
				if typedKey.N.BitLen() < minRSAKeySize {
					return nil, fmt.Errorf("%w: got %d bits", errRSAKeyTooSmall, typedKey.N.BitLen())
				}

				privateKey = typedKey
			default:
				return nil, fmt.Errorf("%w: %T", errUnsupportedKeyType, key)
			}

		case "RSA PRIVATE KEY":
			// PKCS#1 format - RSA only
			rsaKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key in %s: %w", path, parseErr)
			}

			// Validate RSA key size
			if rsaKey.N.BitLen() < minRSAKeySize {
				return nil, fmt.Errorf("%w: got %d bits", errRSAKeyTooSmall, rsaKey.N.BitLen())
			}

			privateKey = rsaKey

		case "PUBLIC KEY":
			key, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse public key in %s: %w", path, parseErr)
			}

			publicKey = key

		case "RSA PUBLIC KEY":
			rsaKey, parseErr := x509.ParsePKCS1PublicKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse PKCS#1 RSA public key in %s: %w", path, parseErr)
			}

			publicKey = rsaKey

		default:
			return nil, fmt.Errorf("%w %q in %s", errUnexpectedPEMBlock, block.Type, path)
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("%w: %s", errMissingPrivateKey, path)
	}

	// Validate public key if present
	if publicKey != nil {
		derivedPublic := privateKey.Public()
		if !publicKeysEqual(derivedPublic, publicKey) {
			return nil, fmt.Errorf("%w: %s", errPublicKeyMismatch, path)
		}
	}

	return privateKey, nil
}

// publicKeysEqual compares two public keys for equality, supporting both RSA and Ed25519
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch aKey := a.(type) {
	case ed25519.PublicKey:
		bKey, ok := b.(ed25519.PublicKey)
		if !ok {
			return false
		}

		return bytes.Equal(aKey, bKey)
	case *rsa.PublicKey:
		bKey, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}

		return aKey.N.Cmp(bKey.N) == 0 && aKey.E == bKey.E
	default:
		return false
	}
}

// NewFileSigner loads a cryptographic private key (RSA or Ed25519) from a PEM file and returns it as a crypto.Signer
func NewFileSigner(path string) (crypto.Signer, error) {
	return loadSignerFromFile(path)
}
