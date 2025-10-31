package tokens

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/oklog/ulid/v2"
)

func TestNewAPITokenKeyring(t *testing.T) {
	key1 := APITokenKey{
		Version: "v1",
		Secret:  bytes.Repeat([]byte{0x01}, 32),
		Status:  KeyStatusActive,
	}

	key2 := APITokenKey{
		Version: "v2",
		Secret:  bytes.Repeat([]byte{0x02}, 32),
		Status:  KeyStatusDeprecated,
	}

	keyring, err := NewAPITokenKeyring(key1, key2)
	if err != nil {
		t.Fatalf("expected keyring to be created: %v", err)
	}

	version, err := keyring.CurrentVersion()
	if err != nil {
		t.Fatalf("expected current version: %v", err)
	}

	if version != "v1" {
		t.Fatalf("expected active version v1, got %s", version)
	}

	v2, err := keyring.Get("v2")
	if err != nil {
		t.Fatalf("expected to retrieve deprecated key: %v", err)
	}

	if v2.Status != KeyStatusDeprecated {
		t.Fatalf("expected key v2 to remain deprecated")
	}

	if err := keyring.Upsert(APITokenKey{
		Version: "v3",
		Secret:  bytes.Repeat([]byte{0x03}, 32),
		Status:  KeyStatusActive,
	}); err != nil {
		t.Fatalf("upsert active key failed: %v", err)
	}

	if version, err = keyring.CurrentVersion(); err != nil {
		t.Fatalf("expected current version after upsert: %v", err)
	}

	if version != "v3" {
		t.Fatalf("expected active version v3, got %s", version)
	}

	v1, err := keyring.Get("v1")
	if err != nil {
		t.Fatalf("expected to retrieve deprecated key v1: %v", err)
	}

	if v1.Status != KeyStatusDeprecated {
		t.Fatalf("expected key v1 to be deprecated after rotation")
	}
}

func TestNewAPITokenKeyringValidation(t *testing.T) {
	_, err := NewAPITokenKeyring()
	if !errors.Is(err, ErrAPITokenNoActiveKey) {
		t.Fatalf("expected ErrAPITokenNoActiveKey, got %v", err)
	}

	_, err = NewAPITokenKeyring(
		APITokenKey{
			Version: "v1",
			Secret:  bytes.Repeat([]byte{0x01}, 32),
			Status:  KeyStatusActive,
		},
		APITokenKey{
			Version: "v2",
			Secret:  bytes.Repeat([]byte{0x02}, 32),
			Status:  KeyStatusActive,
		},
	)
	if !errors.Is(err, ErrAPITokenMultipleActiveKeys) {
		t.Fatalf("expected ErrAPITokenMultipleActiveKeys, got %v", err)
	}

	_, err = NewAPITokenKeyring(
		APITokenKey{
			Version: "v1",
			Secret:  nil,
			Status:  KeyStatusActive,
		},
	)
	if !errors.Is(err, ErrAPITokenSecretMissing) {
		t.Fatalf("expected ErrAPITokenSecretMissing, got %v", err)
	}

	_, err = NewAPITokenKeyring(
		APITokenKey{
			Version: "",
			Secret:  bytes.Repeat([]byte{0x01}, 32),
			Status:  KeyStatusActive,
		},
	)
	if !errors.Is(err, ErrAPITokenMissingKeyVersion) {
		t.Fatalf("expected ErrAPITokenMissingKeyVersion, got %v", err)
	}

	_, err = NewAPITokenKeyring(
		APITokenKey{
			Version: "v1",
			Secret:  bytes.Repeat([]byte{0x01}, 32),
			Status:  KeyStatusDeprecated,
		},
		APITokenKey{
			Version: "v1",
			Secret:  bytes.Repeat([]byte{0x02}, 32),
		},
	)
	if !errors.Is(err, ErrAPITokenDuplicateKeyVersion) {
		t.Fatalf("expected ErrAPITokenDuplicateKeyVersion, got %v", err)
	}

	_, err = NewAPITokenKeyring(
		APITokenKey{
			Version: "v1",
			Secret:  bytes.Repeat([]byte{0x01}, 32),
			Status:  KeyStatusDeprecated,
		},
		APITokenKey{
			Version: "v2",
			Secret:  bytes.Repeat([]byte{0x02}, 32),
			Status:  KeyStatusDeprecated,
		},
	)
	if !errors.Is(err, ErrAPITokenNoActiveKey) {
		t.Fatalf("expected ErrAPITokenNoActiveKey when no key is active, got %v", err)
	}
}

func TestGenerateAndVerifyAPIToken(t *testing.T) {
	keyring, err := NewAPITokenKeyring(APITokenKey{
		Version: "v1",
		Secret:  bytes.Repeat([]byte{0xAA}, 32),
		Status:  KeyStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to create keyring: %v", err)
	}

	tm := &TokenManager{}
	tm.WithAPITokenKeyring(keyring)
	tm.withAPITokenEntropySource(bytes.NewReader(bytes.Repeat([]byte{0xBB}, 64)))

	token, err := tm.GenerateAPIToken()
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}

	if token.TokenID.Compare(ulid.ULID{}) == 0 {
		t.Fatalf("expected token ID to be set")
	}

	if token.KeyVersion != "v1" {
		t.Fatalf("expected key version v1, got %s", token.KeyVersion)
	}

	id, secretBytes, err := parseOpaqueToken(token.Value)
	if err != nil {
		t.Fatalf("expected to parse token: %v", err)
	}

	if id != token.TokenID {
		t.Fatalf("expected parsed token ID to match generated ID")
	}

	if got := opaqueEncoding.EncodeToString(secretBytes); got != token.Secret {
		t.Fatalf("expected secret to match token, got %s", got)
	}

	expected := computeAPITokenDigest(bytes.Repeat([]byte{0xAA}, 32), token.TokenID, secretBytes)
	if !bytes.Equal(expected, token.SecretDigest) {
		t.Fatalf("expected digest bytes to be returned for convenience")
	}

	if gotHash := opaqueEncoding.EncodeToString(expected); gotHash != token.Hash {
		t.Fatalf("expected stored hash %s to match computed %s", token.Hash, gotHash)
	}

	returnedID, err := tm.VerifyAPIToken(token.Value, token.Hash, token.KeyVersion)
	if err != nil {
		t.Fatalf("expected token verification to succeed: %v", err)
	}

	if returnedID != token.TokenID {
		t.Fatalf("expected verification to return token ID")
	}
}

func TestVerifyAPITokenFailures(t *testing.T) {
	keyring, err := NewAPITokenKeyring(APITokenKey{
		Version: "v1",
		Secret:  bytes.Repeat([]byte{0xAA}, 32),
		Status:  KeyStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to create keyring: %v", err)
	}

	tm := &TokenManager{}
	tm.WithAPITokenKeyring(keyring)
	tm.withAPITokenEntropySource(bytes.NewReader(bytes.Repeat([]byte{0xCC}, 32)))

	token, err := tm.GenerateAPIToken()
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}

	if _, err = tm.VerifyAPIToken(token.Value, token.Hash, "missing"); !errors.Is(err, ErrAPITokenKeyVersionUnknown) {
		t.Fatalf("expected ErrAPITokenKeyVersionUnknown, got %v", err)
	}

	if _, err = tm.VerifyAPIToken("bad-format", token.Hash, token.KeyVersion); !errors.Is(err, ErrAPITokenInvalidFormat) {
		t.Fatalf("expected ErrAPITokenInvalidFormat, got %v", err)
	}

	if _, err = tm.VerifyAPIToken(token.Value, "*not-base64*", token.KeyVersion); !errors.Is(err, ErrAPITokenHashInvalid) {
		t.Fatalf("expected ErrAPITokenHashInvalid, got %v", err)
	}

	_, secretBytes, err := parseOpaqueToken(token.Value)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	modified := append([]byte(nil), secretBytes...)
	modified[0] ^= 0xFF

	invalidValue := token.TokenID.String() + "." + opaqueEncoding.EncodeToString(modified)

	if _, err = tm.VerifyAPIToken(invalidValue, token.Hash, token.KeyVersion); !errors.Is(err, ErrAPITokenVerificationFailed) {
		t.Fatalf("expected ErrAPITokenVerificationFailed, got %v", err)
	}

	if err := keyring.Upsert(APITokenKey{
		Version: "v2",
		Secret:  bytes.Repeat([]byte{0xDD}, 32),
		Status:  KeyStatusActive,
	}); err != nil {
		t.Fatalf("failed to promote new active key: %v", err)
	}

	if err := keyring.Upsert(APITokenKey{
		Version: token.KeyVersion,
		Secret:  bytes.Repeat([]byte{0xAA}, 32),
		Status:  KeyStatusRevoked,
	}); err != nil {
		t.Fatalf("failed to revoke previous key: %v", err)
	}

	if _, err = tm.VerifyAPIToken(token.Value, token.Hash, token.KeyVersion); !errors.Is(err, ErrAPITokenKeyRevoked) {
		t.Fatalf("expected ErrAPITokenKeyRevoked, got %v", err)
	}
}

func TestHashAPITokenComponents(t *testing.T) {
	keyring, err := NewAPITokenKeyring(APITokenKey{
		Version: "v1",
		Secret:  bytes.Repeat([]byte{0xAA}, 32),
		Status:  KeyStatusActive,
	})
	if err != nil {
		t.Fatalf("failed to create keyring: %v", err)
	}

	tm := &TokenManager{}
	tm.WithAPITokenKeyring(keyring)
	tm.withAPITokenEntropySource(bytes.NewReader(bytes.Repeat([]byte{0xDD}, 32)))

	token, err := tm.GenerateAPIToken()
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}

	if err := keyring.Upsert(APITokenKey{
		Version: "v2",
		Secret:  bytes.Repeat([]byte{0xEE}, 32),
		Status:  KeyStatusActive,
	}); err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}

	newHash, err := tm.HashAPITokenComponents(token.TokenID, token.Secret, "v2")
	if err != nil {
		t.Fatalf("expected rehash to succeed: %v", err)
	}

	if len(newHash) == 0 {
		t.Fatalf("expected new hash to be returned")
	}

	if _, err = tm.VerifyAPIToken(token.Value, newHash, "v2"); err != nil {
		t.Fatalf("expected verification with rotated key to succeed: %v", err)
	}
}

func TestLoadAPITokenKeyringFromEnv(t *testing.T) {
	secretActive := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x10}, 32))
	secretDeprecated := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x20}, 32))

	t.Setenv("IAM_API_TOKEN_KEY_v1", "active:"+secretActive)
	t.Setenv("IAM_API_TOKEN_KEY_v2", secretDeprecated)

	keyring, err := LoadAPITokenKeyringFromEnv(DefaultAPITokenEnvPrefix)
	if err != nil {
		t.Fatalf("expected keyring to load from env: %v", err)
	}

	version, err := keyring.CurrentVersion()
	if err != nil {
		t.Fatalf("failed to get current version: %v", err)
	}

	if version != "v1" {
		t.Fatalf("expected active version from env to be v1, got %s", version)
	}

	v2, err := keyring.Get("v2")
	if err != nil {
		t.Fatalf("expected to retrieve deprecated key: %v", err)
	}

	if v2.Status != KeyStatusDeprecated {
		t.Fatalf("expected key v2 to be deprecated, got %s", v2.Status)
	}
}

func TestLoadAPITokenKeyringFromEnvErrors(t *testing.T) {
	t.Run("prefix required", func(t *testing.T) {
		if _, err := LoadAPITokenKeyringFromEnv(""); !errors.Is(err, ErrAPITokenEnvPrefixRequired) {
			t.Fatalf("expected ErrAPITokenEnvPrefixRequired, got %v", err)
		}
	})

	t.Run("no keys found", func(t *testing.T) {
		if _, err := LoadAPITokenKeyringFromEnv(DefaultAPITokenEnvPrefix); !errors.Is(err, ErrAPITokenNoKeysFound) {
			t.Fatalf("expected ErrAPITokenNoKeysFound, got %v", err)
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x30}, 32))
		t.Setenv("IAM_API_TOKEN_KEY_v1", "unknown:"+secret)

		if _, err := LoadAPITokenKeyringFromEnv(DefaultAPITokenEnvPrefix); !errors.Is(err, ErrAPITokenInvalidStatus) {
			t.Fatalf("expected ErrAPITokenInvalidStatus, got %v", err)
		}
	})

	t.Run("invalid secret", func(t *testing.T) {
		t.Setenv("IAM_API_TOKEN_KEY_v1", "active:!!!")

		if _, err := LoadAPITokenKeyringFromEnv(DefaultAPITokenEnvPrefix); !errors.Is(err, ErrAPITokenSecretInvalid) {
			t.Fatalf("expected ErrAPITokenSecretInvalid, got %v", err)
		}
	})

	t.Run("missing version suffix", func(t *testing.T) {
		secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x40}, 32))
		t.Setenv(DefaultAPITokenEnvPrefix, "active:"+secret)

		if _, err := LoadAPITokenKeyringFromEnv(DefaultAPITokenEnvPrefix); !errors.Is(err, ErrAPITokenVersionFromEnvMissing) {
			t.Fatalf("expected ErrAPITokenVersionFromEnvMissing, got %v", err)
		}
	})
}

func TestNewAPITokenKeyringFromConfig(t *testing.T) {
	cfg := APITokenConfig{
		Keys: map[string]APITokenKeyConfig{
			"2024-10": {
				Secret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
				Status: "deprecated",
			},
			"2025-01": {
				Secret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
				Status: "active",
			},
		},
	}

	keyring, err := NewAPITokenKeyringFromConfig(cfg)
	if err != nil {
		t.Fatalf("expected keyring from config: %v", err)
	}

	version, err := keyring.CurrentVersion()
	if err != nil {
		t.Fatalf("failed to get active version: %v", err)
	}

	if version != "2025-01" {
		t.Fatalf("expected active version 2025-01, got %s", version)
	}

	deprecated, err := keyring.Get("2024-10")
	if err != nil {
		t.Fatalf("expected to get deprecated key: %v", err)
	}

	if deprecated.Status != KeyStatusDeprecated {
		t.Fatalf("expected key 2024-10 to be deprecated, got %s", deprecated.Status)
	}
}

func TestNewAPITokenKeyringFromConfigErrors(t *testing.T) {
	t.Run("no keys", func(t *testing.T) {
		cfg := APITokenConfig{}
		if _, err := NewAPITokenKeyringFromConfig(cfg); !errors.Is(err, ErrAPITokenNoKeysFound) {
			t.Fatalf("expected ErrAPITokenNoKeysFound, got %v", err)
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		cfg := APITokenConfig{
			Keys: map[string]APITokenKeyConfig{
				"v1": {
					Secret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
					Status: "invalid",
				},
			},
		}

		if _, err := NewAPITokenKeyringFromConfig(cfg); !errors.Is(err, ErrAPITokenInvalidStatus) {
			t.Fatalf("expected ErrAPITokenInvalidStatus, got %v", err)
		}
	})

	t.Run("invalid secret", func(t *testing.T) {
		cfg := APITokenConfig{
			Keys: map[string]APITokenKeyConfig{
				"v1": {
					Secret: "!!!",
					Status: "active",
				},
			},
		}

		if _, err := NewAPITokenKeyringFromConfig(cfg); !errors.Is(err, ErrAPITokenSecretInvalid) {
			t.Fatalf("expected ErrAPITokenSecretInvalid, got %v", err)
		}
	})

	t.Run("missing version", func(t *testing.T) {
		cfg := APITokenConfig{
			Keys: map[string]APITokenKeyConfig{
				"": {
					Secret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
					Status: "active",
				},
			},
		}

		if _, err := NewAPITokenKeyringFromConfig(cfg); !errors.Is(err, ErrAPITokenMissingKeyVersion) {
			t.Fatalf("expected ErrAPITokenMissingKeyVersion, got %v", err)
		}
	})
}

func TestGenerateAPITokenKeyMaterial(t *testing.T) {
	version, secret, err := GenerateAPITokenKeyMaterial()
	if err != nil {
		t.Fatalf("expected key material generation to succeed: %v", err)
	}

	if len(secret) != apiTokenSecretSize {
		t.Fatalf("expected secret size %d, got %d", apiTokenSecretSize, len(secret))
	}

	if _, err := ulid.Parse(version); err != nil {
		t.Fatalf("expected version to be ULID-compatible, got %s: %v", version, err)
	}
}
