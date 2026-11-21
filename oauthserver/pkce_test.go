package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestValidChallenge(t *testing.T) {
	valid := challengeFor(strings.Repeat("a", 43))

	tests := []struct {
		name      string
		challenge string
		method    string
		want      bool
	}{
		{name: "S256 challenge", challenge: valid, method: MethodS256, want: true},
		{name: "plain method", challenge: valid, method: "plain"},
		{name: "empty method", challenge: valid, method: ""},
		{name: "too short", challenge: valid[:42], method: MethodS256},
		{name: "padded", challenge: valid + "=", method: MethodS256},
		{name: "not base64url", challenge: strings.Repeat("+", 43), method: MethodS256},
		{name: "empty challenge", challenge: "", method: MethodS256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ValidChallenge(tc.challenge, tc.method))
		})
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43) + "-._~"
	challenge := challengeFor(verifier)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{name: "matching verifier", verifier: verifier, challenge: challenge, want: true},
		{name: "wrong verifier", verifier: verifier + "x", challenge: challenge},
		{name: "short verifier", verifier: "short", challenge: challenge},
		{name: "short verifier matching its own challenge", verifier: "abc", challenge: challengeFor("abc")},
		{name: "verifier too long", verifier: strings.Repeat("a", 129), challenge: challengeFor(strings.Repeat("a", 129))},
		{name: "verifier with invalid characters", verifier: strings.Repeat("a", 42) + "!", challenge: challengeFor(strings.Repeat("a", 42) + "!")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, VerifyPKCE(tc.verifier, tc.challenge))
		})
	}
}
