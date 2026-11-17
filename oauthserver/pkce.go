package oauthserver

import (
	"regexp"

	"github.com/theopenlane/utils/keygen"
)

// MethodS256 is the only PKCE method accepted (OAuth 2.1 drops "plain")
const MethodS256 = "S256"

// verifierPattern is the RFC 7636 code_verifier grammar: 43-128 unreserved characters
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// challengePattern is a base64url-encoded SHA-256 digest (43 characters, no padding)
var challengePattern = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)

// ValidChallenge reports whether a code_challenge is well formed for S256
func ValidChallenge(challenge, method string) bool {
	return method == MethodS256 && challengePattern.MatchString(challenge)
}

// VerifyPKCE checks a code_verifier's RFC 7636 grammar and that it matches the stored S256 code_challenge
func VerifyPKCE(verifier, challenge string) bool {
	if !verifierPattern.MatchString(verifier) {
		return false
	}

	return keygen.Equal(keygen.S256Challenge(verifier), challenge)
}
