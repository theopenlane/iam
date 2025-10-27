package tokens

import (
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestNewFileSigner(t *testing.T) {
	signer, err := NewFileSigner("testdata/01GE6191AQTGMCJ9BN0QC3CCVG.pem")
	require.NoError(t, err)

	_, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519 public key")
}

func TestNewFileSignerRSA(t *testing.T) {
	signer, err := NewFileSigner("testdata/rsa_2048_test.pem")
	require.NoError(t, err)

	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "expected rsa public key")
	require.GreaterOrEqual(t, rsaPub.N.BitLen(), 2048, "expected at least 2048-bit RSA key")
}

func TestNewFileSignerInvalidPath(t *testing.T) {
	_, err := NewFileSigner("does-not-exist.pem")
	require.Error(t, err)
}

func TestDetectSigningMethod(t *testing.T) {
	t.Run("Ed25519 key detects EdDSA", func(t *testing.T) {
		signer, err := NewFileSigner("testdata/01GE6191AQTGMCJ9BN0QC3CCVG.pem")
		require.NoError(t, err)

		method := signingMethodForKey(signer)
		require.Equal(t, jwt.SigningMethodEdDSA, method)
	})

	t.Run("RSA key detects RS256", func(t *testing.T) {
		signer, err := NewFileSigner("testdata/rsa_2048_test.pem")
		require.NoError(t, err)

		method := signingMethodForKey(signer)
		require.Equal(t, jwt.SigningMethodRS256, method)
	})
}
