# Tokens Package

The tokens package provides JWT token creation, signing, and validation using Ed25519 (`EdDSA`).

## Architecture

The package provides two interfaces:

- **`Issuer`** - Focused on token creation and signing (recommended for new code)
- **`TokenManager`** - Wraps Issuer and adds validation, blacklist, and replay prevention

For most use cases, use `Issuer` for token creation and a separate validator for verification. This provides cleaner separation of concerns.

## Quick Start

### Using Issuer (Recommended)

```go
import (
    "github.com/theopenlane/iam/tokens"
    "time"
)

// Create configuration
config := tokens.Config{
    Audience:        "https://api.example.com",
    Issuer:          "https://api.example.com",
    AccessDuration:  1 * time.Hour,
    RefreshDuration: 2 * time.Hour,
    RefreshOverlap:  -15 * time.Minute,
    Keys:            map[string]string{"01ABC": "/path/to/key.pem"},
}

// Create issuer for token creation
issuer, err := tokens.NewIssuer(config)
if err != nil {
    panic(err)
}

// Create tokens
claims := &tokens.Claims{
    RegisteredClaims: jwt.RegisteredClaims{
        Subject: "user-123",
    },
    Email: "user@example.com",
}

accessToken, refreshToken, err := issuer.CreateTokens(claims)
if err != nil {
    panic(err)
}

// Parse token (without validating claims)
parsedClaims, err := issuer.Parse(accessToken)

// Get JWKS for external validation
keys, err := issuer.Keys()
```

### Using TokenManager (Includes Validation)

TokenManager wraps Issuer and adds validation with optional Redis-backed blacklist and replay prevention:

```go
// Create token manager with Redis features
config := tokens.Config{
    Audience:        "https://api.example.com",
    Issuer:          "https://api.example.com",
    AccessDuration:  1 * time.Hour,
    RefreshDuration: 2 * time.Hour,
    RefreshOverlap:  -15 * time.Minute,
    Keys:            map[string]string{"01ABC": "/path/to/key.pem"},
    Redis: tokens.RedisConfig{
        Enabled: true,
        Config: cache.Config{
            Address: "localhost:6379",
        },
    },
}

tm, err := tokens.New(config)

// Create and validate tokens
accessToken, refreshToken, err := tm.CreateTokens(claims)

// Verify with blacklist and replay prevention
validatedClaims, err := tm.VerifyWithContext(ctx, accessToken)

// Revoke token
err = tm.RevokeToken(ctx, tokenID, ttl)
```

## Opaque API Tokens

Personal access tokens and other long-lived API credentials can be issued as opaque strings that never persist the raw secret. Configure a symmetric keyring, generate the token, and store only the derived hash alongside the key version. All key material is supplied declaratively via configuration/environment so deployments stay static—rotations happen by updating secrets and restarting the service, never by calling runtime helpers.

```go
// For illustration in tests or local tools you can construct a keyring manually.
// Production deployments typically rely on config-driven loading shown below.
keyring, _ := tokens.NewAPITokenKeyring(
    tokens.APITokenKey{
        Version: "01HKH8M2MD6QXQ6Y8Q8KQKJ4ZW", // ULID keeps versions lexicographically ordered by creation time
        Secret:  []byte("32-bytes-of-key-material......"),
        Status:  tokens.KeyStatusActive,
    },
)
tm.WithAPITokenKeyring(keyring)

opaque, _ := tm.GenerateAPIToken()
// Persist opaque.TokenID (ULID), opaque.Hash, and opaque.KeyVersion.
// Only opaque.Value should shown to the caller

// Functional options let you reshape the token format when needed. For example,
// add a static prefix, change the delimiter, and increase the secret size:
customFormat := []tokens.APITokenOption{
    tokens.WithAPITokenPrefix("ol_"),
    tokens.WithAPITokenDelimiter("-"),
    tokens.WithAPITokenSecretSize(48),
}
opaqueCustom, _ := tm.GenerateAPIToken(customFormat...)
```

When a request presents the token, look up the stored metadata and verify:

```go
tokenID, err := tm.VerifyAPIToken(token.Value, storedHash, storedKeyVersion)
if err != nil {
    return err
}

// If you emitted a custom format when issuing the token, pass the same options
// so verification applies the matching parsing rules.
customID, err := tm.VerifyAPIToken(opaqueCustom.Value, storedHash, storedKeyVersion, customFormat...)
if err != nil {
    return err
}
// customID now contains the ULID portion of the custom formatted token.
```

During rotation, publish a new key (mark it `active` in config), demote the prior key to `deprecated`, and redeploy; the loader rebuilds the keyring on startup and `HashAPITokenComponents` lets you re-hash persisted tokens lazily as they are presented.

Opaque token keys are provided through configuration so the process remains fully declarative.

```go
config.APITokens = tokens.APITokenConfig{
    Enabled: true,
    SecretSize: tokens.DefaultAPITokenSecretSize,
    Delimiter:  tokens.DefaultAPITokenDelimiter,
    Prefix:     "",
    Keys: map[string]tokens.APITokenKeyConfig{
        "01HKH8M2MD6QXQ6Y8Q8KQKJ4ZW": {Status: "active", Secret: "<base64 secret>"},
        "01HKH7WPR4Y9YH0JYH0A7RZG9F": {Status: "deprecated", Secret: "<base64 secret>"},
    },
    // Optional: fall back to environment prefix if you prefer per-key env vars
    EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
}
```

You can generate a new key version and secret using the helper below (ideal for wiring into a small CLI):

```go
version, secret, _ := tokens.GenerateAPITokenKeyMaterial()
fmt.Printf("version=%s\nsecret=%s\n", version, base64.StdEncoding.EncodeToString(secret))
```

Secrets can be supplied directly in configuration (for example `CORE_AUTH_TOKEN_APITOKENS_KEYS_01HKH8M2MD6QXQ6Y8Q8KQKJ4ZW_STATUS=active` and `..._SECRET=<base64 secret>`) or via the flat environment loader by keeping `EnvPrefix` populated and publishing entries as `<EnvPrefix><version>=<status>:<base64-secret>`. Only one key should be marked `active`; additional keys can be `deprecated` or `revoked`. If the status segment is omitted, the loader defaults the first key to active. To rotate, publish the new key (mark it `active`), demote the old one to `deprecated`, and redeploy—the startup loader will rebuild the keyring without any runtime API calls.

### CLI Generator

For convenience a CLI lives at `tokens/examples`. Run it with `go run ./tokens/examples` (or build the binary) to emit new key material plus rotation instructions. Pass `--json` to produce machine-readable output and set `API_TOKEN_KEY_JSON=true` to enable JSON via environment variable.

## Key Material

- PEM files referenced in `tokens.Config.Keys` **must** contain an Ed25519 key
  pair encoded as PKCS#8 (`PRIVATE KEY`) plus a companion `PUBLIC KEY` block.
- Existing RSA material must be rotated or regenerated. A simple Go snippet can
  produce compatible files:

  ```go
  package main

  import (
  	"crypto/ed25519"
  	"crypto/rand"
  	"crypto/x509"
  	"encoding/pem"
  	"os"
  )

  func main() {
  	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

  	f, _ := os.Create("signing-key.pem")
  	defer f.Close()

  	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
  	_ = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

  	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
  	_ = pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
  }
  ```

- JWKS responses emitted by `TokenManager.Keys()` advertise `alg=EdDSA`,
  `kty=OKP`, and `crv=Ed25519`, which is compatible with the lestrrat-go/jwx
  toolchain used elsewhere in this repository.

## API Changes

### New Architecture

The package now provides:

- **`Issuer`** - New interface for token creation and signing
  - `NewIssuer(config)` - Create issuer from configuration
  - `NewIssuerWithKey(key, config)` - Create issuer with single key
  - `CreateAccessToken(claims)` - Create access token
  - `CreateRefreshToken(accessToken)` - Create refresh token
  - `CreateTokens(claims)` - Create both tokens in one call
  - `Sign(token)` - Sign a token
  - `Parse(tks)` - Parse without claim validation
  - `Keys()` - Get JWKS

- **`TokenManager`** - Wraps Issuer, adds validation
  - Inherits all Issuer methods
  - Adds `Verify()` and `VerifyWithContext()` for validation
  - Adds blacklist and replay prevention features

## Signer Helpers

Helper constructors are available when loading keys from files:

- `NewFileSigner(path)` loads an Ed25519 key pair from a PEM file and returns it as a `crypto.Signer`.

### Token Blacklist

Allows revoking individual tokens or suspending all tokens for a user. Useful for:
- Immediate token revocation on logout
- User account suspension
- Compromised token mitigation

### Configuration

Enable Redis features by adding the `redis` configuration to your `tokens.Config`:

```go
import (
    "github.com/theopenlane/iam/tokens"
    "github.com/theopenlane/utils/cache"
)

config := tokens.Config{
    Audience:        "https://api.example.com",
    Issuer:          "https://api.example.com",
    AccessDuration:  1 * time.Hour,
    RefreshDuration: 2 * time.Hour,
    RefreshOverlap:  -15 * time.Minute,
    Keys:            map[string]string{"01ABC": "/path/to/key.pem"},
    Redis: tokens.RedisConfig{
        Enabled: true,
        Config: cache.Config{
            Enabled:  true,
            Address:  "localhost:6379",
            Password: "secret",
            DB:       0,
        },
        BlacklistPrefix: "token:blacklist:",  // Redis key prefix for blacklist
    },
}

tm, err := tokens.New(config)
```
