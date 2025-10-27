package tokens

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	errInvalidEd25519Key  = errors.New("signing key is not a valid ed25519 key")
	errUnexpectedPEMBlock = errors.New("unexpected PEM block type")
	errMissingPrivateKey  = errors.New("missing ed25519 private key")
	errPublicKeyMismatch  = errors.New("public key mismatch")
	errUnsupportedHash    = errors.New("unsupported hash function for Ed25519")
)

// signerLoader defines the interface for loading cryptographic signers from filesystem paths.
type signerLoader interface {
	Load(source string) (crypto.Signer, error)
}

// defaultSignerLoader is a stateless implementation of signerLoader that loads Ed25519 signers
// from filesystem paths. This zero-sized struct follows the strategy pattern, allowing the token
// manager to remain decoupled from specific loading implementations.
type defaultSignerLoader struct{}

// Load loads an Ed25519 signer from a PEM-encoded file at the specified path.
func (defaultSignerLoader) Load(source string) (crypto.Signer, error) {
	return loadEd25519SignerFromFile(source)
}

// loadEd25519SignerFromFile reads and parses a PEM-encoded Ed25519 private key from the specified file path.
// The file may contain both PRIVATE KEY and PUBLIC KEY blocks. If a public key is present, it is validated
// against the derived public key from the private key to ensure they match.
func loadEd25519SignerFromFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key from %s: %w", path, err)
	}

	var private ed25519.PrivateKey

	var public ed25519.PublicKey

	for {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		switch block.Type {
		case "PRIVATE KEY":
			key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse private key in %s: %w", path, parseErr)
			}

			edKey, ok := key.(ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("%w (private)", errInvalidEd25519Key)
			}

			private = edKey
		case "PUBLIC KEY":
			key, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse public key in %s: %w", path, parseErr)
			}

			edKey, ok := key.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%w (public)", errInvalidEd25519Key)
			}

			public = edKey
		default:
			return nil, fmt.Errorf("%w %q in %s", errUnexpectedPEMBlock, block.Type, path)
		}
	}

	if private == nil {
		return nil, fmt.Errorf("%w: %s", errMissingPrivateKey, path)
	}

	derivedPublic := private.Public().(ed25519.PublicKey) //nolint:forcetypeassert
	if public != nil && !bytes.Equal(derivedPublic, public) {
		return nil, fmt.Errorf("%w: %s", errPublicKeyMismatch, path)
	}

	return private, nil
}

// NewFileSigner loads an Ed25519 private key from a PEM file and returns it as a crypto.Signer.
func NewFileSigner(path string) (crypto.Signer, error) {
	return loadEd25519SignerFromFile(path)
}
