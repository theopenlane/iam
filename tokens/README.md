# Tokens Package

The token manager now signs and validates JWTs using Ed25519 (`EdDSA`).
This section captures the practical changes and configuration knobs that differ
from the previous RSA (`RS256`) implementation.

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

Breaking changes introduced by the EdDSA migration:

- `tokens.NewWithKey` now accepts a `crypto.Signer` instead of `*rsa.PrivateKey`.
- `(*TokenManager).AddSigningKey` requires a `crypto.Signer` and returns an error
  if the signer cannot supply an Ed25519 public key.

Existing call sites must pass Ed25519 private keys (which implement
`crypto.Signer`) and handle the potential error return.

## Validation Notes

- `validator` continues to enforce issuer and audience but now restricts tokens
  to `EdDSA` signatures.
- `tokens.ParseUnverified` and `tokens.ParseUnverifiedTokenClaims` validate
  Ed25519 signatures during parsing so behaviour matches the previous RSA flow.

## Signer Helpers

Helper constructors are available when loading keys from files:

- `NewFileSigner(path)` loads an Ed25519 key pair from a PEM file and returns it as a `crypto.Signer`.
