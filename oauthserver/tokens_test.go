package oauthserver

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

func newTestKeyring(t *testing.T) (*tokens.APITokenKeyring, []byte) {
	t.Helper()

	secret := make([]byte, tokens.MinAPITokenSecretLength)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	keyring, err := tokens.NewAPITokenKeyring(tokens.APITokenKey{Version: "v1", Secret: secret, Status: tokens.KeyStatusActive})
	require.NoError(t, err)

	return keyring, secret
}

func newTestIssuer(t *testing.T) *TokenIssuer {
	t.Helper()

	keyring, _ := newTestKeyring(t)

	issuer, err := NewTokenIssuer((&tokens.TokenManager{}).WithAPITokenKeyring(keyring))
	require.NoError(t, err)

	return issuer
}

func stored(tok *Token) StoredToken {
	return StoredToken{ID: tok.ID.String(), Kind: tok.Kind, Hash: tok.Hash, KeyVersion: tok.KeyVersion}
}

func TestTokenKindPrefix(t *testing.T) {
	tests := []struct {
		name string
		kind TokenKind
		want string
	}{
		{name: "request", kind: KindRequest, want: RequestPrefix},
		{name: "code", kind: KindCode, want: CodePrefix},
		{name: "access", kind: KindAccess, want: AccessTokenPrefix},
		{name: "refresh", kind: KindRefresh, want: RefreshTokenPrefix},
		{name: "unknown", kind: "BOGUS", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.kind.Prefix())
		})
	}
}

func TestTokenKindValid(t *testing.T) {
	tests := []struct {
		name string
		kind TokenKind
		want bool
	}{
		{name: "request", kind: KindRequest, want: true},
		{name: "code", kind: KindCode, want: true},
		{name: "access", kind: KindAccess, want: true},
		{name: "refresh", kind: KindRefresh, want: true},
		{name: "unknown", kind: "BOGUS"},
		{name: "empty", kind: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.kind.Valid())
		})
	}
}

func TestKindOf(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want TokenKind
	}{
		{name: "request", raw: RequestPrefix + "x", want: KindRequest},
		{name: "code", raw: CodePrefix + "x", want: KindCode},
		{name: "access", raw: AccessTokenPrefix + "x", want: KindAccess},
		{name: "refresh", raw: RefreshTokenPrefix + "x", want: KindRefresh},
		{name: "api token", raw: "tola_api-token"},
		{name: "empty", raw: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, KindOf(tc.raw))
		})
	}
}

func TestIsAccessToken(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "access token", raw: AccessTokenPrefix + "x", want: true},
		{name: "refresh token", raw: RefreshTokenPrefix + "x"},
		{name: "api token", raw: "tola_api-token"},
		{name: "empty", raw: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsAccessToken(tc.raw))
		})
	}
}

func TestNewTokenIssuer(t *testing.T) {
	keyring, _ := newTestKeyring(t)

	tests := []struct {
		name    string
		tm      *tokens.TokenManager
		wantErr error
	}{
		{name: "nil token manager", wantErr: ErrKeyringRequired},
		{name: "no keyring", tm: &tokens.TokenManager{}, wantErr: ErrKeyringRequired},
		{name: "keyring with an active key", tm: (&tokens.TokenManager{}).WithAPITokenKeyring(keyring)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := NewTokenIssuer(tc.tm)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, issuer)
		})
	}
}

func TestIssue(t *testing.T) {
	tests := []struct {
		name          string
		kind          TokenKind
		removeKeyring bool
		wantErr       error
	}{
		{name: "request", kind: KindRequest},
		{name: "code", kind: KindCode},
		{name: "access", kind: KindAccess},
		{name: "refresh", kind: KindRefresh},
		{name: "unknown kind", kind: "BOGUS", wantErr: ErrTokenInvalid},
		{name: "keyring removed after startup", kind: KindAccess, removeKeyring: true, wantErr: tokens.ErrAPITokenKeyringNotConfigured},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyring, _ := newTestKeyring(t)
			tm := (&tokens.TokenManager{}).WithAPITokenKeyring(keyring)

			issuer, err := NewTokenIssuer(tm)
			require.NoError(t, err)

			if tc.removeKeyring {
				tm.WithAPITokenKeyring(nil)
			}

			tok, err := issuer.Issue(tc.kind)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.kind, tok.Kind)
			assert.True(t, strings.HasPrefix(tok.Value, tc.kind.Prefix()), tok.Value)
			assert.Equal(t, tc.kind, KindOf(tok.Value))
			assert.NotContains(t, tok.Hash, tok.Value)
			assert.True(t, tok.ExpiresAt.After(time.Now()))

			other, err := issuer.Issue(tc.kind)
			require.NoError(t, err)
			assert.NotEqual(t, tok.Value, other.Value)
		})
	}
}

func TestLookup(t *testing.T) {
	issuer := newTestIssuer(t)

	access, err := issuer.Issue(KindAccess)
	require.NoError(t, err)

	refresh, err := issuer.Issue(KindRefresh)
	require.NoError(t, err)

	_, secret, ok := strings.Cut(access.Value, ".")
	require.True(t, ok)

	tests := []struct {
		name     string
		raw      string
		wantKind TokenKind
		wantID   string
		wantErr  error
	}{
		{name: "access token", raw: access.Value, wantKind: KindAccess, wantID: access.ID.String()},
		{name: "refresh token", raw: refresh.Value, wantKind: KindRefresh, wantID: refresh.ID.String()},
		{name: "refresh token renamed to access keys on the presented kind", raw: AccessTokenPrefix + strings.TrimPrefix(refresh.Value, RefreshTokenPrefix), wantKind: KindAccess, wantID: refresh.ID.String()},
		{name: "empty", raw: "", wantErr: ErrTokenInvalid},
		{name: "prefix only", raw: AccessTokenPrefix, wantErr: ErrTokenInvalid},
		{name: "garbage after prefix", raw: AccessTokenPrefix + "garbage", wantErr: ErrTokenInvalid},
		{name: "unknown prefix", raw: "nope_" + secret, wantErr: ErrTokenInvalid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, id, err := issuer.Lookup(tc.raw)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantKind, kind)
			assert.Equal(t, tc.wantID, id.String())
		})
	}
}

func TestVerify(t *testing.T) {
	issuer := newTestIssuer(t)

	tok, err := issuer.Issue(KindAccess)
	require.NoError(t, err)

	other, err := issuer.Issue(KindAccess)
	require.NoError(t, err)

	refresh, err := issuer.Issue(KindRefresh)
	require.NoError(t, err)

	idPart, _, ok := strings.Cut(tok.Value, ".")
	require.True(t, ok)

	withID := stored(tok)
	withID.ID = other.ID.String()

	withKeyVersion := stored(tok)
	withKeyVersion.KeyVersion = "v2"

	withMalformedID := stored(tok)
	withMalformedID.ID = "not-a-ulid"

	tests := []struct {
		name    string
		raw     string
		stored  StoredToken
		wantErr error
	}{
		{name: "matching record", raw: tok.Value, stored: stored(tok)},
		{name: "another token's record", raw: tok.Value, stored: stored(other), wantErr: ErrTokenInvalid},
		{name: "forged secret", raw: idPart + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), stored: stored(tok), wantErr: ErrTokenInvalid},
		{name: "stored id differs", raw: tok.Value, stored: withID, wantErr: ErrTokenInvalid},
		{name: "unknown key version", raw: tok.Value, stored: withKeyVersion, wantErr: ErrTokenInvalid},
		{name: "malformed stored id", raw: tok.Value, stored: withMalformedID, wantErr: ErrTokenInvalid},
		{name: "refresh token renamed to access", raw: AccessTokenPrefix + strings.TrimPrefix(refresh.Value, RefreshTokenPrefix), stored: stored(refresh), wantErr: ErrTokenKindMismatch},
		{name: "unknown prefix", raw: "nope_x", stored: stored(tok), wantErr: ErrTokenKindMismatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := issuer.Verify(tc.raw, tc.stored)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			assert.NoError(t, err)
		})
	}

	t.Run("key rotation", func(t *testing.T) {
		keyring, v1 := newTestKeyring(t)

		rotated, err := NewTokenIssuer((&tokens.TokenManager{}).WithAPITokenKeyring(keyring))
		require.NoError(t, err)

		old, err := rotated.Issue(KindRefresh)
		require.NoError(t, err)

		v2 := make([]byte, tokens.MinAPITokenSecretLength)
		_, err = rand.Read(v2)
		require.NoError(t, err)

		require.NoError(t, keyring.Upsert(tokens.APITokenKey{Version: "v2", Secret: v2, Status: tokens.KeyStatusActive}))
		assert.NoError(t, rotated.Verify(old.Value, stored(old)))

		fresh, err := rotated.Issue(KindRefresh)
		require.NoError(t, err)
		assert.Equal(t, "v2", fresh.KeyVersion)

		require.NoError(t, keyring.Upsert(tokens.APITokenKey{Version: "v1", Secret: v1, Status: tokens.KeyStatusRevoked}))
		assert.ErrorIs(t, rotated.Verify(old.Value, stored(old)), ErrTokenInvalid)
		assert.NoError(t, rotated.Verify(fresh.Value, stored(fresh)))
	})
}
