package totp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	// keyTTL is the expiration time for a key in redis
	keyTTL = 30 * time.Second
	// otpExpiration is the expiration time for an OTP code
	otpExpiration = 5 * time.Minute
	// numericCode is a string of numbers
	numericCode = "0123456"
	// alphanumericCode is a string of numbers and letters
	alphanumericCode = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// otpRedos is a minimal interface for go-redis with OTP codes
type otpRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Close() error
}

// Secret stores a versioned secret key for cryptography functions
type Secret struct {
	Version int
	Key     string
}

// Hash contains a hash of a OTP code
type Hash struct {
	CodeHash       string         `json:"code_hash"`
	ExpiresAt      int64          `json:"expires_at"`
	Address        string         `json:"address"`
	DeliveryMethod DeliveryMethod `json:"delivery_method"`
}

// OTP is a credential validator for User OTP codes
type OTP struct {
	// codeLength is the length of a randomly generated code
	codeLength         int
	ttl                int
	issuer             string
	secrets            []Secret
	db                 otpRedis
	recoveryCodeCount  int
	recoveryCodeLength int
}

// OTPCode creates a random code and hash
func (o *OTP) OTPCode(address string, method DeliveryMethod) (code string, hash string, err error) {
	c, err := String(o.codeLength, numericCode)
	if err != nil {
		return "", "", ErrCannotGenerateRandomString
	}

	h, err := toOTPHash(c, address, method)
	if err != nil {
		return "", "", ErrCannotHashOTPString
	}

	return c, h, nil
}

// TOTPSecret assigns a TOTP secret for a user for use in code generation.
// TOTP secrets are encrypted by a pre-configured secret key and decrypted
// only during validation. Encrypted keys are versioned to assist with migrations
// and backwards compatibility in the event an older secret ever needs to
// be deprecated.
func (o *OTP) TOTPSecret(u *User) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      o.issuer,
		AccountName: u.DefaultName(),
	})
	if err != nil {
		log.Err(err).Msg("failed to generate TOTP secret")

		return "", ErrFailedToGenerateSecret
	}

	encryptedKey, err := o.encrypt(key.Secret())
	if err != nil {
		log.Err(err).Msg("failed to generate TOTP secret")

		return "", ErrCannotEncryptSecret
	}

	return encryptedKey, nil
}

// TOTPQRString returns a string containing account details for TOTP code generation
func (o *OTP) TOTPQRString(u *User) (string, error) {
	// otpauth://totp/TheOpenLane:matt@google.com?secret=JBSWY3DPEHPK3PXP&issuer=TheOpenLane
	secret, err := o.TOTPDecryptedSecret(u.TFASecret)
	if err != nil {
		return "", err
	}

	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", o.issuer)
	v.Set("algorithm", otp.AlgorithmSHA1.String())
	v.Set("period", strconv.Itoa(o.ttl))
	v.Set("digits", "6")
	otpauth := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + o.issuer + ":" + u.DefaultName(),
		RawQuery: v.Encode(),
	}

	return otpauth.String(), nil
}

// TOTPDecryptedSecret returns a string containing the decrypted TOTP secret
func (o *OTP) TOTPDecryptedSecret(secret string) (string, error) {
	secret, err := o.decrypt(secret)
	if err != nil {
		return "", ErrFailedToGetSecretForQR
	}

	return secret, nil
}

// ValidateOTP checks if a User's OTP code is valid
// users can input secrets sent by SMS or email (needs to be implemented separately)
func (o *OTP) ValidateOTP(code string, hash string) error {
	otp, err := FromOTPHash(hash)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	if now >= otp.ExpiresAt {
		return ErrInvalidCode("code is expired")
	}

	h, err := OTPHash(code)
	if err != nil {
		return ErrInvalidCode("code submission failed")
	}

	if subtle.ConstantTimeCompare([]byte(h), []byte(otp.CodeHash)) != 1 {
		return ErrInvalidCode("incorrect code provided")
	}

	return nil
}

// ValidateTOTP checks if a User's TOTP is valid - first validate the TOTP against the user's secret key
// and then check if the code has been set in redis, indicating that it has been used in the past thirty seconds
// codes that have been validated are cached to prevent immediate reuse
func (o *OTP) ValidateTOTP(ctx context.Context, user *User, code string) error {
	secret, err := o.decrypt(user.TFASecret)
	if err != nil {
		return ErrCannotDecryptSecret
	}

	if !totp.Validate(code, secret) {
		return ErrIncorrectCodeProvided
	}

	key := fmt.Sprintf("%s_%s", user.ID, code)

	// redis is not configured, we can't invalidate the code for future checks
	if o.db == nil {
		log.Debug().Msg("redis is not configured, code will not be invalidated")

		return nil
	}

	// Validated code has previously been used in the past thirty seconds
	if err = o.db.Get(ctx, key).Err(); err == nil {
		return ErrCodeIsNoLongerValid
	}

	// No code found in redis, indicating the code is valid. Set it to the
	// DB to prevent reuse
	if errors.Is(err, redis.Nil) {
		return o.db.Set(ctx, key, true, keyTTL).Err()
	}

	return ErrFailedToValidateCode
}

// latestSecret returns the most recent versioned secret key
func (o *OTP) latestSecret() (Secret, error) {
	var secret Secret

	for _, s := range o.secrets {
		if s.Version >= secret.Version {
			secret = s
		}
	}

	if secret.Key == "" {
		return secret, ErrNoSecretKey
	}

	return secret, nil
}

// secretByVersion returns a versioned secret key
func (o *OTP) secretByVersion(version int) (Secret, error) {
	var secret Secret

	for _, s := range o.secrets {
		if s.Version == version {
			secret = s
			break
		}
	}

	if secret.Key == "" {
		return secret, ErrNoSecretKeyForVersion
	}

	return secret, nil
}

// encrypt encrypts a string using the most recent versioned secret key
// in this service and returns the value as a base64 encoded string
// with a versioning prefix
func (o *OTP) encrypt(s string) (string, error) {
	secret, err := o.latestSecret()
	if err != nil {
		return "", err
	}

	key := sha256.Sum256([]byte(secret.Key))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", ErrFailedToCreateCipherBlock
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrFailedToCreateCipherBlock
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrFailedToCreateCipherText
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(s), nil)

	encoded := base64.StdEncoding.EncodeToString(cipherText)

	return fmt.Sprintf("%v:%s", secret.Version, encoded), nil
}

// decrypt decrypts an encrypted string using a versioned secret
func (o *OTP) decrypt(encryptedTxt string) (string, error) {
	// Split and parse the version prefix
	v := strings.Split(encryptedTxt, ":")[0]
	encryptedTxt = strings.TrimPrefix(encryptedTxt, fmt.Sprintf("%s:", v))

	version, err := strconv.Atoi(v)
	if err != nil {
		return "", ErrFailedToDetermineSecretVersion
	}

	secret, err := o.secretByVersion(version)
	if err != nil {
		return "", err
	}

	key := sha256.Sum256([]byte(secret.Key))

	decoded, err := base64.StdEncoding.DecodeString(encryptedTxt)
	if err != nil {
		return "", ErrCannotDecodeSecret
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", ErrFailedToCreateCipherBlock
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrFailedToCreateCipherBlock
	}

	if len(decoded) < gcm.NonceSize() {
		return "", ErrCipherTextTooShort
	}

	nonce := decoded[:gcm.NonceSize()]
	cipherText := decoded[gcm.NonceSize():]

	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", ErrCannotDecryptSecret
	}

	return string(plainText), nil
}

// toOTPHash creates a hash from a OTP code
func toOTPHash(code, address string, method DeliveryMethod) (string, error) {
	codeHash, err := OTPHash(code)
	if err != nil {
		return "", ErrFailedToHashCode
	}

	expiresAt := time.Now().Add(otpExpiration).Unix()

	hash := &Hash{
		CodeHash:       codeHash,
		Address:        address,
		DeliveryMethod: method,
		ExpiresAt:      expiresAt,
	}

	b, err := json.Marshal(hash)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FromOTPHash parses an OTP hash string to individual parts
func FromOTPHash(otpHash string) (*Hash, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(otpHash)
	if err != nil {
		return nil, ErrCannotDecodeOTPHash
	}

	var o Hash

	if err = json.Unmarshal(decoded, &o); err != nil {
		return nil, ErrInvalidOTPHashFormat
	}

	return &o, nil
}

// GenerateOTP generates a Time-Based One-Time Password (TOTP).
func GenerateOTP(secret, issuer, account string) (string, error) {
	secretBytes := []byte(secret)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Secret:      secretBytes,
		// You can customize the TOTP options as needed.
	})
	if err != nil {
		return "", err
	}

	otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		return "", err
	}

	return otpCode, nil
}

// GenerateRecoveryCodes generates a list of recovery codes
func (o *OTP) GenerateRecoveryCodes() []string {
	codes := []string{}

	for range o.recoveryCodeCount {
		code, err := String(o.recoveryCodeLength, alphanumericCode)
		if err != nil {
			continue
		}

		codes = append(codes, code)
	}

	return codes
}
