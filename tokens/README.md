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

### Breaking Changes

- `tokens.New()` and `tokens.NewWithKey()` now accept `crypto.Signer` instead of `*rsa.PrivateKey`
- `(*TokenManager).AddSigningKey()` requires `crypto.Signer` and returns error
- Multi-algorithm support: EdDSA (Ed25519) is primary, RSA (RS256/RS384/RS512) supported for migration

## Validation Notes

- `validator` continues to enforce issuer and audience but now restricts tokens
  to `EdDSA` signatures.
- `tokens.ParseUnverified` and `tokens.ParseUnverifiedTokenClaims` validate
  Ed25519 signatures during parsing so behaviour matches the previous RSA flow.

## Signer Helpers

Helper constructors are available when loading keys from files:

- `NewFileSigner(path)` loads an Ed25519 key pair from a PEM file and returns it as a `crypto.Signer`.

## Redis-Backed Security Features

The tokens package supports optional Redis-backed features for enhanced security:

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

### Backward Compatibility

The `WithBlacklist()` method remains available for:
- Testing with mock implementations
- Runtime configuration changes
- Custom Redis client management

```go
// Override config-based initialization
tm.WithBlacklist(customBlacklist)
```

When Redis is disabled (`Redis.Enabled = false`), the package uses a no-op blacklist implementation that gracefully degrades functionality without errors.
