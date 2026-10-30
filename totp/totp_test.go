package totp

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOTPManager(t *testing.T) {
	codeLength := 10
	svc := NewOTP(
		WithCodeLength(codeLength),
	)

	code, hash, err := svc.OTPCode("mitb@theopenlane.io", Email)
	assert.NoErrorf(t, err, "failed to create code: %v", err)

	assert.Len(t, code, codeLength, "incorrect code length")

	err = svc.ValidateOTP(code, hash)
	assert.NoErrorf(t, err, "failed to validate code: %v", err)
}

func TestTOTPSecret(t *testing.T) {
	svc := NewOTP(
		WithIssuer("authenticator.local"),
		WithSecret(Secret{
			Version: 1,
			Key:     "9f0c6da662f018b58b04a093e2dbb2e1",
		}),
	).(*OTP)
	user := &User{
		IsTOTPAllowed:     true,
		IsEmailOTPAllowed: false,
		Phone: sql.NullString{
			String: "+17853931234",
			Valid:  true,
		},
	}

	secret, err := svc.TOTPSecret(user)
	assert.NoError(t, err)
	assert.NotNil(t, secret, "no secret generated")
}

func TestTOTPQRString(t *testing.T) {
	svc := NewOTP(
		WithIssuer("authenticator.local"),
		WithSecret(Secret{
			Version: 1,
			Key:     "9f0c6da662f018b58b04a093e2dbb2e1",
		}),
	).(*OTP)
	encrypted, err := svc.encrypt("5UEP2YNN7GWAMUFHS65SH7ONWZVZ3LKF")
	assert.NoError(t, err)

	user := &User{
		IsTOTPAllowed:     true,
		IsEmailOTPAllowed: false,
		TFASecret:         encrypted,
		Phone: sql.NullString{
			String: "+17853931234",
			Valid:  true,
		},
	}

	qrString, err := svc.TOTPQRString(user)
	assert.NoError(t, err)

	expectedString := "otpauth://totp/authenticator.local:+17853931234?algorithm=" +
		"SHA1&digits=6&issuer=authenticator.local&period=30&secret=" +
		"5UEP2YNN7GWAMUFHS65SH7ONWZVZ3LKF"
	assert.Equal(t, expectedString, qrString, "TOTP QR string does not match")
}

func TestTOTPDecryptedSecret(t *testing.T) {
	svc := NewOTP(
		WithIssuer("authenticator.local"),
		WithSecret(Secret{
			Version: 1,
			Key:     "9f0c6da662f018b58b04a093e2dbb2e1",
		}),
	).(*OTP)

	encrypted, err := svc.encrypt("5UEP2YNN7GWAMUFHS65SH7ONWZVZ3LKF")
	assert.NoError(t, err)

	decryptedSecret, err := svc.TOTPDecryptedSecret(encrypted)
	assert.NoError(t, err)

	expectedString := "5UEP2YNN7GWAMUFHS65SH7ONWZVZ3LKF"
	assert.Equal(t, expectedString, decryptedSecret)
}

func TestEncryptsWithLatestSecret(t *testing.T) {
	svc := &OTP{
		secrets: []Secret{
			{Version: 0, Key: "key-0"},
			{Version: 1, Key: "key-1"},
			{Version: 2, Key: "key-2"},
		},
	}
	secret := "some-secret-value"
	s, err := svc.encrypt(secret)
	assert.NoError(t, err, "failed to encrypt secret")

	assert.NotEqual(t, secret, s, "value not encrypted")
	assert.True(t, strings.HasPrefix(s, "2:"), "value not encrypted with latest secret")

	s, err = svc.decrypt(s)
	assert.NoError(t, err, "failed to decrypt secret")

	assert.Equal(t, secret, s, "value not decrypted")
}
func TestGenerateRecoveryCodes(t *testing.T) {
	o := &OTP{
		recoveryCodeCount:  5,
		recoveryCodeLength: 8,
	}

	codes := o.GenerateRecoveryCodes()

	assert.Len(t, codes, 5, "incorrect number of recovery codes generated")

	for _, code := range codes {
		assert.Len(t, code, 8, "incorrect recovery code length")
	}
}

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOTP("ABCDEFGHIJKL", "issuer", "user@example.com")
	assert.NoError(t, err)
	assert.Len(t, otp, 6, "incorrect otp length")
}

func TestValidateTOTPRejectsReplay(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)

	defer mr.Close()

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rc.Close()

	svc := NewOTP(
		WithIssuer("authenticator.local"),
		WithSecret(Secret{Version: 1, Key: "9f0c6da662f018b58b04a093e2dbb2e1"}),
		WithRedis(rc),
	)

	user := &User{ID: "user-1", Email: sql.NullString{String: "mitb@theopenlane.io", Valid: true}}

	encrypted, err := svc.TOTPSecret(user)
	require.NoError(t, err)

	user.TFASecret = encrypted

	plain, err := svc.TOTPDecryptedSecret(encrypted)
	require.NoError(t, err)

	code, err := totp.GenerateCode(plain, time.Now())
	require.NoError(t, err)

	require.NoError(t, svc.ValidateTOTP(context.Background(), user, code))
	assert.ErrorIs(t, svc.ValidateTOTP(context.Background(), user, code), ErrCodeIsNoLongerValid)

	// the claim must outlive the full validation window of the previous period
	assert.Equal(t, keyTTL, mr.TTL("user-1_"+code))
}
