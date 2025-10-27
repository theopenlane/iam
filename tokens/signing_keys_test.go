package tokens

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewFileSigner(t *testing.T) {
	signer, err := NewFileSigner("testdata/01GE6191AQTGMCJ9BN0QC3CCVG.pem")
	require.NoError(t, err)

	_, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519 public key")
}

func TestNewFileSignerInvalidPath(t *testing.T) {
	_, err := NewFileSigner("does-not-exist.pem")
	require.Error(t, err)
}
