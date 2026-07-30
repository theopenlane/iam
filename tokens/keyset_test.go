package tokens_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

func keySetConfig() tokens.Config {
	return tokens.Config{
		Audience:        "http://localhost:3000",
		Issuer:          "http://localhost:3001",
		AccessDuration:  time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}
}

func newSigner(t *testing.T) crypto.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return priv
}

func keySetClaims() *tokens.Claims {
	return &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "01H6PGFB4T34D4WWEXQMAGJNMK"},
	}
}

func tokenKeyID(t *testing.T, tks string) string {
	t.Helper()

	token, _, err := jwt.NewParser().ParseUnverified(tks, &jwt.RegisteredClaims{})
	require.NoError(t, err)

	kid, ok := token.Header["kid"].(string)
	require.True(t, ok)

	return kid
}

func TestSetKeySetSelectsSigningKey(t *testing.T) {
	t.Parallel()

	tm, err := tokens.NewWithKey(newSigner(t), keySetConfig())
	require.NoError(t, err)

	first, second := newSigner(t), newSigner(t)

	require.NoError(t, tm.SetKeySet(tokens.KeySet{
		Signing: map[string]crypto.Signer{"first": first, "second": second},
		KID:     "second",
	}))

	require.Equal(t, "second", tm.CurrentKeyID())

	atks, _, err := tm.CreateTokenPair(keySetClaims())
	require.NoError(t, err)
	require.Equal(t, "second", tokenKeyID(t, atks))

	// the key the manager was constructed with is gone once the set is replaced
	jwks, err := tm.Keys()
	require.NoError(t, err)
	require.Equal(t, 2, jwks.Len())
}

func TestSetKeySetVerificationOnlyKeysStayValid(t *testing.T) {
	t.Parallel()

	retiring := newSigner(t)

	tm, err := tokens.NewWithKey(retiring, keySetConfig())
	require.NoError(t, err)

	require.NoError(t, tm.SetKeySet(tokens.KeySet{
		Signing: map[string]crypto.Signer{"retiring": retiring},
		KID:     "retiring",
	}))

	old, _, err := tm.CreateTokenPair(keySetClaims())
	require.NoError(t, err)

	// the retiring key loses its signer but keeps verifying, as it would once its
	// private material is replaced on disk
	replacement := newSigner(t)

	require.NoError(t, tm.SetKeySet(tokens.KeySet{
		Signing:      map[string]crypto.Signer{"replacement": replacement},
		Verification: map[string]crypto.PublicKey{"retiring": retiring.Public()},
		KID:          "replacement",
	}))

	fresh, _, err := tm.CreateTokenPair(keySetClaims())
	require.NoError(t, err)
	require.Equal(t, "replacement", tokenKeyID(t, fresh))

	claims, err := tm.Verify(old)
	require.NoError(t, err)
	require.Equal(t, "01H6PGFB4T34D4WWEXQMAGJNMK", claims.Subject)

	_, err = tm.Verify(fresh)
	require.NoError(t, err)

	// both kids are published so external validators can still resolve the old one
	jwks, err := tm.Keys()
	require.NoError(t, err)
	require.Equal(t, 2, jwks.Len())
}

func TestSetKeySetRejectsUnusableSets(t *testing.T) {
	t.Parallel()

	tm, err := tokens.NewWithKey(newSigner(t), keySetConfig())
	require.NoError(t, err)

	signer := newSigner(t)
	before := tm.CurrentKeyID()

	// a kid that cannot sign is never silently swapped for another key
	err = tm.SetKeySet(tokens.KeySet{
		Signing: map[string]crypto.Signer{"present": signer},
		KID:     "absent",
	})
	require.ErrorIs(t, err, tokens.ErrUnknownSigningKey)

	err = tm.SetKeySet(tokens.KeySet{
		Verification: map[string]crypto.PublicKey{"verify-only": signer.Public()},
	})
	require.ErrorIs(t, err, tokens.ErrTokenManagerFailedInit)

	err = tm.SetKeySet(tokens.KeySet{
		Signing: map[string]crypto.Signer{"": signer},
	})
	require.ErrorIs(t, err, tokens.ErrEmptySigningKeyID)

	// a rejected set leaves the issuer untouched
	require.Equal(t, before, tm.CurrentKeyID())
}

func TestSetKeySetConcurrentWithTokenTraffic(t *testing.T) {
	t.Parallel()

	tm, err := tokens.NewWithKey(newSigner(t), keySetConfig())
	require.NoError(t, err)

	rotations := []tokens.KeySet{}

	for _, kid := range []string{"alpha", "beta", "gamma"} {
		signer := newSigner(t)
		rotations = append(rotations, tokens.KeySet{
			Signing: map[string]crypto.Signer{kid: signer},
			KID:     kid,
		})
	}

	require.NoError(t, tm.SetKeySet(rotations[0]))

	var readers, rotator sync.WaitGroup

	done := make(chan struct{})

	// rotate the key set underneath live traffic; without the issuer lock this races
	// with every reader below
	rotator.Add(1)

	go func() {
		defer rotator.Done()

		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}

			require.NoError(t, tm.SetKeySet(rotations[i%len(rotations)]))
		}
	}()

	for range 8 {
		readers.Add(1)

		go func() {
			defer readers.Done()

			for range 200 {
				atks, _, err := tm.CreateTokenPair(keySetClaims())
				require.NoError(t, err)

				// the signing key may have rotated between signing and verifying, so a
				// verification failure here is expected; the point is that neither call panics
				_, _ = tm.Verify(atks)

				_, err = tm.Keys()
				require.NoError(t, err)

				require.NotEmpty(t, tm.CurrentKeyID())
			}
		}()
	}

	readers.Wait()
	close(done)
	rotator.Wait()
}
