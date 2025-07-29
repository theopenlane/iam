package sessions

import "errors"

var (
	// ErrInvalidSession is returned when the session is invalid
	ErrInvalidSession = errors.New("invalid session provided")
	// ErrSigningKeyIsRequired is returned when the signing key is not provided
	ErrSigningKeyIsRequired = errors.New("signing key is required - use GenerateSecureKey() to create one or configure Redis for persistent key management")
	// ErrEncryptionKeyIsRequired is returned when the encryption key is not provided
	ErrEncryptionKeyIsRequired = errors.New("encryption key is required - use GenerateSecureKey() to create one or configure Redis for persistent key management")
)
