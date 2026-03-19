package tokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/theopenlane/utils/ulids"
)

const (
	nonceLength                           = 64
	keyLength                             = 64
	expirationDays                        = 7
	resetTokenExpirationMinutes           = 15
	inviteExpirationDays                  = 14
	downloadTokenDefaultExpirationMinutes = 10
)

// URLToken represents a token that can be signed and verified
type URLToken interface {
	Validate() error
	SetNonce([]byte)
}

// signingInfoProvider represents a token that can provide signing information for signing and verifying
type signingInfoProvider interface {
	signingInfo() *SigningInfo
}

// managedURLToken represents a token that can be signed, verified, and provides signing information
type managedURLToken interface {
	URLToken
	signingInfoProvider
}

// Ensure our token types implement URLToken
var (
	_ URLToken = (*VerificationToken)(nil)
	_ URLToken = (*ResetToken)(nil)
	_ URLToken = (*OrgInviteToken)(nil)
	_ URLToken = (*DownloadToken)(nil)
)

// NewVerificationToken creates a token struct from an email address that expires
// in 7 days
func NewVerificationToken(email string) (token *VerificationToken, err error) {
	if email == "" {
		return nil, ErrMissingEmail
	}

	token = &VerificationToken{
		Email: email,
	}

	return initializeURLToken(token, time.Hour*24*expirationDays)
}

// VerificationToken packages an email address with random data and an expiration
// time so that it can be serialized and hashed into a token which can be sent to users
type VerificationToken struct {
	Email string `msgpack:"email"`
	SigningInfo
}

// Sign creates a base64 encoded string from the token data so that it can be sent to
// users as part of a URL. The returned secret should be stored in the database so that
// the string can be recomputed when verifying a user provided token.
func (t *VerificationToken) Sign() (string, []byte, error) {
	return signURLToken(t)
}

// Validate checks that the token has required fields
func (t *VerificationToken) Validate() error {
	if t.Email == "" {
		return ErrTokenMissingEmail
	}

	return nil
}

// Verify checks that a token was signed with the secret and is not expired
func (t *VerificationToken) Verify(signature string, secret []byte) error {
	return verifyURLToken(t, signature, secret)
}

// NewResetToken creates a token struct from a user ID that expires in 15 minutes
func NewResetToken(id ulid.ULID) (token *ResetToken, err error) {
	if ulids.IsZero(id) {
		return nil, ErrMissingUserID
	}

	token = &ResetToken{
		UserID: id,
	}

	return initializeURLToken(token, time.Minute*resetTokenExpirationMinutes)
}

// ResetToken packages a user ID with random data and an expiration time so that it can
// be serialized and hashed into a token which can be sent to users
type ResetToken struct {
	UserID ulid.ULID `msgpack:"user_id"`
	SigningInfo
}

// Sign creates a base64 encoded string from the token data so that it can be sent to
// users as part of a URL. The returned secret should be stored in the database so that
// the string can be recomputed when verifying a user provided token
func (t *ResetToken) Sign() (string, []byte, error) {
	return signURLToken(t)
}

// Validate checks that the token has required fields
func (t *ResetToken) Validate() error {
	if ulids.IsZero(t.UserID) {
		return ErrTokenMissingUserID
	}

	return nil
}

// Verify checks that a token was signed with the secret and is not expired
func (t *ResetToken) Verify(signature string, secret []byte) error {
	return verifyURLToken(t, signature, secret)
}

// NewSigningInfo creates new signing info with a time expiration
func NewSigningInfo(expires time.Duration) (info SigningInfo, err error) {
	if expires == 0 {
		return info, ErrExpirationIsRequired
	}

	info = SigningInfo{
		ExpiresAt: time.Now().UTC().Add(expires).Truncate(time.Microsecond),
		Nonce:     make([]byte, nonceLength),
	}

	if _, err = rand.Read(info.Nonce); err != nil {
		return info, ErrFailedSigning
	}

	return info, nil
}

// SigningInfo contains an expiration time and a nonce that is used to sign the token
type SigningInfo struct {
	ExpiresAt time.Time `msgpack:"expires_at"`
	Nonce     []byte    `msgpack:"nonce"`
}

// signingInfo returns the signing info for the token
func (d *SigningInfo) signingInfo() *SigningInfo {
	return d
}

// SetNonce sets the nonce used to reconstruct and verify a token signature.
func (d *SigningInfo) SetNonce(nonce []byte) {
	d.Nonce = nonce
}

// IsExpired checks if the token is expired based on the current time and the expiration time in the signing info
func (d SigningInfo) IsExpired() bool {
	return d.ExpiresAt.Before(time.Now())
}

// initializeURLToken initializes the signing info for a token and returns the token ready to be signed
func initializeURLToken[T managedURLToken](token T, expires time.Duration) (T, error) {
	signingInfo, err := NewSigningInfo(expires)
	if err != nil {
		return token, err
	}

	*token.signingInfo() = signingInfo

	return token, nil
}

// signURLToken marshals and signs any token that embeds SigningInfo
func signURLToken[T managedURLToken](token T) (string, []byte, error) {
	return token.signingInfo().SignToken(token)
}

// verifyURLToken provides common verification logic for all token types
func verifyURLToken[T managedURLToken](token T, signature string, secret []byte) error {
	if err := token.Validate(); err != nil {
		return err
	}

	return token.signingInfo().VerifyToken(token, signature, secret)
}

// SignToken marshals and signs any token that embeds SigningInfo
func (d SigningInfo) SignToken(token interface{}) (string, []byte, error) {
	data, err := msgpack.Marshal(token)
	if err != nil {
		return "", nil, err
	}

	return d.signData(data)
}

// VerifyToken provides common verification logic for all token types
func (d SigningInfo) VerifyToken(token URLToken, signature string, secret []byte) error {
	if d.IsExpired() {
		return ErrTokenExpired
	}

	if len(secret) != nonceLength+keyLength {
		return ErrInvalidSecret
	}

	// Update the token's nonce from the secret
	token.SetNonce(secret[0:nonceLength])

	data, err := msgpack.Marshal(token)
	if err != nil {
		return err
	}

	return d.verifyData(data, signature, secret)
}

// Create a signature from raw data and a nonce. The resulting signature is safe to be used in a URL
func (d SigningInfo) signData(data []byte) (_ string, secret []byte, err error) {
	// Compute hash with a random 64 byte key
	key := make([]byte, keyLength)
	if _, err = rand.Read(key); err != nil {
		return "", nil, err
	}

	mac := hmac.New(sha256.New, key)
	if _, err = mac.Write(data); err != nil {
		return "", nil, err
	}

	// Include the nonce with the key so that the token can be reconstructed later
	secret = make([]byte, nonceLength+keyLength)
	copy(secret[0:nonceLength], d.Nonce)
	copy(secret[nonceLength:], key)

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), secret, nil
}

// Verify data using the signature and secret
func (d SigningInfo) verifyData(data []byte, signature string, secret []byte) (err error) {
	// Compute hash to verify the user token
	mac := hmac.New(sha256.New, secret[nonceLength:])
	if _, err = mac.Write(data); err != nil {
		return err
	}

	// Decode the user token
	var token []byte

	if token, err = base64.RawURLEncoding.DecodeString(signature); err != nil {
		return err
	}

	// Check if the recomputed token matches the user token
	if !hmac.Equal(mac.Sum(nil), token) {
		return ErrTokenInvalid
	}

	return nil
}

// NewOrgInvitationToken creates a token struct from an email address that expires
// in 14 days
func NewOrgInvitationToken(email string, orgID ulid.ULID) (token *OrgInviteToken, err error) {
	if email == "" {
		return nil, ErrInviteTokenMissingEmail
	}

	if ulids.IsZero(orgID) {
		return nil, ErrInviteTokenMissingOrgID
	}

	token = &OrgInviteToken{
		Email: email,
		OrgID: orgID,
	}

	return initializeURLToken(token, time.Hour*24*inviteExpirationDays)
}

// OrgInviteToken packages an email address with random data and an expiration
// time so that it can be serialized and hashed into a token which can be sent to users
type OrgInviteToken struct {
	Email string    `msgpack:"email"`
	OrgID ulid.ULID `msgpack:"organization_id"`
	SigningInfo
}

// Sign creates a base64 encoded string from the token data so that it can be sent to
// users as part of a URL. The returned secret should be stored in the database so that
// the string can be recomputed when verifying a user provided token.
func (t *OrgInviteToken) Sign() (string, []byte, error) {
	return signURLToken(t)
}

// Validate checks that the token has required fields
func (t *OrgInviteToken) Validate() error {
	if t.Email == "" {
		return ErrInviteTokenMissingEmail
	}

	if ulids.IsZero(t.OrgID) {
		return ErrInviteTokenMissingOrgID
	}

	return nil
}

// Verify checks that a token was signed with the secret and is not expired
func (t *OrgInviteToken) Verify(signature string, secret []byte) error {
	return verifyURLToken(t, signature, secret)
}

// DownloadToken encodes the metadata required to authorize a proxied download.
type DownloadToken struct {
	ObjectURI string    `msgpack:"object_uri"`
	UserID    ulid.ULID `msgpack:"user_id,omitempty"`
	OrgID     ulid.ULID `msgpack:"org_id,omitempty"`
	SigningInfo
}

type downloadTokenConfig struct {
	userID    ulid.ULID
	orgID     ulid.ULID
	expiresIn time.Duration
}

// DownloadTokenOption mutates the configuration for a new download token.
type DownloadTokenOption func(*downloadTokenConfig)

// NewDownloadToken creates a download token with the provided options.
func NewDownloadToken(objectURI string, opts ...DownloadTokenOption) (*DownloadToken, error) {
	if objectURI == "" {
		return nil, ErrDownloadTokenMissingObjectURI
	}

	cfg := downloadTokenConfig{
		expiresIn: time.Minute * downloadTokenDefaultExpirationMinutes,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	token := &DownloadToken{
		ObjectURI: objectURI,
		UserID:    cfg.userID,
		OrgID:     cfg.orgID,
	}

	return initializeURLToken(token, cfg.expiresIn)
}

// WithDownloadTokenUserID associates the token with a user identifier.
func WithDownloadTokenUserID(id ulid.ULID) DownloadTokenOption {
	return func(cfg *downloadTokenConfig) {
		cfg.userID = id
	}
}

// WithDownloadTokenOrgID associates the token with an organization identifier.
func WithDownloadTokenOrgID(id ulid.ULID) DownloadTokenOption {
	return func(cfg *downloadTokenConfig) {
		cfg.orgID = id
	}
}

// WithDownloadTokenExpiresIn customizes the lifetime of the download token.
func WithDownloadTokenExpiresIn(duration time.Duration) DownloadTokenOption {
	return func(cfg *downloadTokenConfig) {
		cfg.expiresIn = duration
	}
}

// Sign returns a URL-safe signature and secret for the token.
func (t *DownloadToken) Sign() (string, []byte, error) {
	return signURLToken(t)
}

// Validate ensures the token contains the expected metadata.
func (t *DownloadToken) Validate() error {
	if t.ObjectURI == "" {
		return ErrDownloadTokenMissingObjectURI
	}

	return nil
}

// Verify checks that the signature and secret are valid for the token.
func (t *DownloadToken) Verify(signature string, secret []byte) error {
	return verifyURLToken(t, signature, secret)
}
