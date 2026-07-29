package tokens

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/oklog/ulid/v2"
)

// KeySet is the complete set of key material an issuer serves
type KeySet struct {
	// Signing holds the private keys eligible to sign, keyed by kid
	Signing map[string]crypto.Signer
	// Verification holds public keys that verify but never sign, keyed by kid
	Verification map[string]crypto.PublicKey
	// KID names the key in Signing to sign with; empty lets the issuer select one
	KID string
}

// Issuer handles JWT token creation and signing. It manages signing keys and
// provides methods to create access tokens, refresh tokens, and sign them
type Issuer struct {
	mu                   sync.RWMutex
	conf                 Config
	currentKeyID         string
	currentKey           crypto.Signer
	currentSigningMethod jwt.SigningMethod
	keys                 map[string]crypto.PublicKey
	signingKeys          map[string]crypto.Signer
	kidEntropy           io.Reader
	refreshAudience      string
	loader               signerLoader
	keyLifecycle         *keyLifecycleManager
	jwksCache            *jwksCache
}

// NewIssuer creates a new Issuer with the specified configuration.
// Keys are loaded from the paths specified in conf.Keys
func NewIssuer(conf Config) (*Issuer, error) {
	if err := conf.Validate(); err != nil {
		return nil, ErrConfigIsInvalid
	}

	issuer := &Issuer{
		conf:            conf,
		keys:            make(map[string]crypto.PublicKey),
		signingKeys:     make(map[string]crypto.Signer),
		keyLifecycle:    newKeyLifecycleManager(),
		jwksCache:       newJWKSCache(conf.JWKSCacheTTL),
		refreshAudience: resolveRefreshAudience(conf),
		kidEntropy: &ulid.LockedMonotonicReader{
			MonotonicReader: ulid.Monotonic(rand.Reader, 0),
		},
		loader: defaultSignerLoader{},
	}

	keyIDs := make([]string, 0, len(conf.Keys))

	for kid := range conf.Keys {
		keyIDs = append(keyIDs, kid)
	}

	sort.Strings(keyIDs)

	loaded := make([]loadedKey, 0, len(keyIDs))

	for _, kid := range keyIDs {
		path := conf.Keys[kid]

		signer, err := issuer.loader.Load(path)
		if err != nil {
			return nil, newParseError("path - retrieve", path, err)
		}

		if err = issuer.AddKey(kid, signer); err != nil {
			return nil, err
		}

		info := loadedKey{kid: kid}

		if parsed, err := ulid.Parse(kid); err == nil {
			info.ulid = parsed
			info.hasULID = true
		}

		loaded = append(loaded, info)
	}

	issuer.mu.Lock()
	issuer.selectInitialKeyLocked(loaded, conf.KID)
	issuer.mu.Unlock()

	if issuer.currentKey == nil {
		return nil, ErrTokenManagerFailedInit
	}

	issuer.conf.KID = issuer.currentKeyID

	return issuer, nil
}

// NewIssuerWithKey creates a new Issuer with a single signing key
func NewIssuerWithKey(key crypto.Signer, conf Config) (*Issuer, error) {
	if err := conf.Validate(); err != nil {
		return nil, ErrConfigIsInvalid
	}

	issuer := &Issuer{
		conf:            conf,
		keys:            make(map[string]crypto.PublicKey),
		signingKeys:     make(map[string]crypto.Signer),
		keyLifecycle:    newKeyLifecycleManager(),
		jwksCache:       newJWKSCache(conf.JWKSCacheTTL),
		refreshAudience: resolveRefreshAudience(conf),
		kidEntropy: &ulid.LockedMonotonicReader{
			MonotonicReader: ulid.Monotonic(rand.Reader, 0),
		},
	}

	kid, err := issuer.genKeyID()
	if err != nil {
		return nil, err
	}

	if err = issuer.AddKey(kid.String(), key); err != nil {
		return nil, err
	}

	issuer.currentKey = key
	issuer.currentKeyID = kid.String()
	issuer.currentSigningMethod = signingMethodForKey(key)
	issuer.conf.KID = issuer.currentKeyID

	return issuer, nil
}

// Sign an access or refresh token and return the signed token string
func (i *Issuer) Sign(token *jwt.Token) (string, error) {
	i.mu.RLock()
	key, kid := i.currentKey, i.currentKeyID
	i.mu.RUnlock()

	if key == nil || kid == "" {
		return "", ErrTokenManagerFailedInit
	}

	token.Header["kid"] = kid

	return token.SignedString(key)
}

// signingMethod returns the signing method of the current signing key
func (i *Issuer) signingMethod() jwt.SigningMethod {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.currentSigningMethod
}

// CreateAccessToken creates an access token from the provided claims.
func (i *Issuer) CreateAccessToken(claims *Claims) (*jwt.Token, error) {
	return i.createAccessTokenWithDuration(claims, i.conf.AccessDuration)
}

// createAccessTokenWithDuration creates an access token with a specified duration.
func (i *Issuer) createAccessTokenWithDuration(claims *Claims, duration time.Duration) (*jwt.Token, error) {
	now := time.Now()
	sub := claims.Subject

	kid, err := i.genKeyID()
	if err != nil {
		return nil, err
	}

	issueTime := jwt.NewNumericDate(now)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        strings.ToLower(kid.String()),
		Subject:   sub,
		Audience:  jwt.ClaimStrings{i.conf.Audience},
		Issuer:    i.conf.Issuer,
		IssuedAt:  issueTime,
		NotBefore: issueTime,
		ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
	}

	return jwt.NewWithClaims(i.signingMethod(), claims), nil
}

// CreateRefreshToken creates a refresh token from an access token.
func (i *Issuer) CreateRefreshToken(accessToken *jwt.Token) (*jwt.Token, error) {
	accessClaims, ok := accessToken.Claims.(*Claims)
	if !ok {
		return nil, ErrFailedRetrieveClaimsFromToken
	}

	audience := accessClaims.Audience
	audience = append(audience, i.RefreshAudience())

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessClaims.ID,
			Audience:  audience,
			Issuer:    accessClaims.Issuer,
			Subject:   accessClaims.Subject,
			IssuedAt:  accessClaims.IssuedAt,
			NotBefore: jwt.NewNumericDate(accessClaims.ExpiresAt.Add(i.conf.RefreshOverlap)),
			ExpiresAt: jwt.NewNumericDate(accessClaims.IssuedAt.Add(i.conf.RefreshDuration)),
		},
		OrgID: accessClaims.OrgID,
	}

	return jwt.NewWithClaims(i.signingMethod(), claims), nil
}

// CreateTokens creates and signs both access and refresh tokens in one step.
func (i *Issuer) CreateTokens(claims *Claims) (accessToken, refreshToken string, err error) {
	var atk, rtk *jwt.Token

	if atk, err = i.CreateAccessToken(claims); err != nil {
		return "", "", fmt.Errorf("could not create access token: %w", err)
	}

	if rtk, err = i.CreateRefreshToken(atk); err != nil {
		return "", "", fmt.Errorf("could not create refresh token: %w", err)
	}

	if accessToken, err = i.Sign(atk); err != nil {
		return "", "", fmt.Errorf("could not sign access token: %w", err)
	}

	if refreshToken, err = i.Sign(rtk); err != nil {
		return "", "", fmt.Errorf("could not sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// Parse parses a token without validating claims (but does verify signature).
func (i *Issuer) Parse(tks string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods(allowedAlgorithms), jwt.WithoutClaimsValidation())
	claims := &Claims{}

	if _, err := parser.ParseWithClaims(tks, claims, i.keyFunc); err != nil {
		return nil, err
	}

	return claims, nil
}

// Keys returns the JWKS with public keys for external use
func (i *Issuer) Keys() (jwk.Set, error) {
	if cached, ok := i.jwksCache.Get(); ok {
		return cached, nil
	}

	i.mu.RLock()
	snapshot := maps.Clone(i.keys)
	i.mu.RUnlock()

	keys := jwk.NewSet()

	for kid, pubkey := range snapshot {
		key, err := jwk.Import(pubkey)
		if err != nil {
			return nil, err
		}

		if err = key.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}

		if err = key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return nil, err
		}

		if meta, ok := i.keyLifecycle.GetMetadata(kid); ok {
			if err = key.Set(jwk.AlgorithmKey, meta.Algorithm); err != nil {
				return nil, err
			}
		}

		if err = keys.AddKey(key); err != nil {
			return nil, err
		}
	}

	i.jwksCache.Set(keys)

	return keys, nil
}

// RefreshAudience returns the refresh audience for tokens
func (i *Issuer) RefreshAudience() string {
	return i.refreshAudience
}

// resolveRefreshAudience derives the refresh audience from the configured audience or issuer
// It is computed once during construction so reads never mutate the issuer
func resolveRefreshAudience(conf Config) string {
	if conf.RefreshAudience != "" {
		return conf.RefreshAudience
	}

	aud, err := url.Parse(conf.Issuer)
	if err != nil {
		return DefaultRefreshAudience
	}

	return aud.ResolveReference(&url.URL{Path: "/v1/refresh"}).String()
}

// CurrentKey returns the ULID of the current signing key if it is ULID formatted
func (i *Issuer) CurrentKey() ulid.ULID {
	if id, err := ulid.Parse(i.CurrentKeyID()); err == nil {
		return id
	}

	return nilID
}

// CurrentKeyID returns the identifier of the current signing key
func (i *Issuer) CurrentKeyID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.currentKeyID
}

// SetKeySet atomically replaces the issuer's key material, letting callers retire a
// signing key without invalidating tokens it already signed
func (i *Issuer) SetKeySet(ks KeySet) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	keys := make(map[string]crypto.PublicKey, len(ks.Signing)+len(ks.Verification))
	signingKeys := make(map[string]crypto.Signer, len(ks.Signing))

	for kid, signer := range ks.Signing {
		if kid == "" {
			return ErrEmptySigningKeyID
		}

		keys[kid] = signer.Public()
		signingKeys[kid] = signer
	}

	for kid, publicKey := range ks.Verification {
		if kid == "" {
			return ErrEmptySigningKeyID
		}

		// a kid that can sign is never downgraded to verification only
		if _, ok := keys[kid]; !ok {
			keys[kid] = publicKey
		}
	}

	if len(signingKeys) == 0 {
		return ErrTokenManagerFailedInit
	}

	if ks.KID != "" {
		if _, ok := signingKeys[ks.KID]; !ok {
			return ErrUnknownSigningKey
		}
	}

	i.keys = keys
	i.signingKeys = signingKeys

	for kid, publicKey := range keys {
		i.keyLifecycle.AddKey(kid, signingMethodForPublicKey(publicKey).Alg())
	}

	for _, kid := range i.keyLifecycle.List() {
		if _, ok := keys[kid]; !ok {
			i.keyLifecycle.RemoveKey(kid)
		}
	}

	i.jwksCache.Invalidate()

	i.currentKey = nil
	i.currentKeyID = ""
	i.currentSigningMethod = nil

	i.selectInitialKeyLocked(loadedKeysFrom(signingKeys), ks.KID)

	if i.currentKey == nil {
		return ErrTokenManagerFailedInit
	}

	i.conf.KID = i.currentKeyID

	return nil
}

// loadedKeysFrom builds the kid metadata selectInitialKeyLocked ranges over, in a stable order
func loadedKeysFrom(signingKeys map[string]crypto.Signer) []loadedKey {
	kids := make([]string, 0, len(signingKeys))
	for kid := range signingKeys {
		kids = append(kids, kid)
	}

	sort.Strings(kids)

	loaded := make([]loadedKey, 0, len(kids))

	for _, kid := range kids {
		info := loadedKey{kid: kid}
		if parsed, err := ulid.Parse(kid); err == nil {
			info.ulid = parsed
			info.hasULID = true
		}

		loaded = append(loaded, info)
	}

	return loaded
}

// AddKey registers a new signing key with the issuer
func (i *Issuer) AddKey(kid string, signer crypto.Signer) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.addKeyLocked(kid, signer)
}

// addKeyLocked registers a new signing key; callers must hold the write lock
func (i *Issuer) addKeyLocked(kid string, signer crypto.Signer) error {
	if kid == "" {
		return ErrEmptySigningKeyID
	}

	publicKey := signer.Public()

	i.keys[kid] = publicKey
	i.signingKeys[kid] = signer

	signingMethod := signingMethodForKey(signer)

	if i.keyLifecycle != nil {
		i.keyLifecycle.AddKey(kid, signingMethod.Alg())
	}

	i.jwksCache.Invalidate()

	if i.currentKey == nil {
		i.currentKey = signer
		i.currentKeyID = kid
		i.currentSigningMethod = signingMethod
		i.conf.KID = kid

		return nil
	}

	newULID, newErr := ulid.Parse(kid)
	newIsULID := newErr == nil
	currentULID, currentErr := ulid.Parse(i.currentKeyID)
	currentIsULID := currentErr == nil

	switch {
	case newIsULID && !currentIsULID:
		i.currentKey = signer
		i.currentKeyID = kid
		i.currentSigningMethod = signingMethod
		i.conf.KID = kid
	case newIsULID && currentIsULID && newULID.Time() > currentULID.Time():
		i.currentKey = signer
		i.currentKeyID = kid
		i.currentSigningMethod = signingMethod
		i.conf.KID = kid
	}

	return nil
}

// UseSigningKeyID sets the current signing key to the specified key ID.
func (i *Issuer) UseSigningKeyID(kid string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key, ok := i.signingKeys[kid]
	if !ok {
		return ErrUnknownSigningKey
	}

	i.currentKey = key
	i.currentKeyID = kid
	i.currentSigningMethod = signingMethodForKey(key)
	i.conf.KID = kid

	return nil
}

// RemoveSigningKeyByID removes a signing key from the issuer
func (i *Issuer) RemoveSigningKeyByID(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	delete(i.keys, kid)
	delete(i.signingKeys, kid)

	i.jwksCache.Invalidate()

	if len(i.signingKeys) == 0 {
		i.currentKey = nil
		i.currentKeyID = ""
		i.conf.KID = ""

		return
	}

	if i.currentKeyID == kid {
		remaining := make([]loadedKey, 0, len(i.signingKeys))

		keyIDs := make([]string, 0, len(i.signingKeys))
		for id := range i.signingKeys {
			keyIDs = append(keyIDs, id)
		}

		sort.Strings(keyIDs)

		for _, id := range keyIDs {
			info := loadedKey{kid: id}
			if parsed, err := ulid.Parse(id); err == nil {
				info.ulid = parsed
				info.hasULID = true
			}

			remaining = append(remaining, info)
		}

		i.currentKey = nil
		i.currentKeyID = ""
		i.selectInitialKeyLocked(remaining, i.conf.KID)

		if i.currentKey != nil {
			i.conf.KID = i.currentKeyID
		}
	}
}

// Config returns the issuer configuration
func (i *Issuer) Config() Config {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.conf
}

// keyFunc is the jwt.Keyfunc used for token verification
func (i *Issuer) keyFunc(token *jwt.Token) (any, error) {
	alg := token.Method.Alg()

	if !slices.Contains(allowedAlgorithms, alg) {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"]) //nolint:err113
	}

	kid, ok := token.Header["kid"]
	if !ok {
		return nil, ErrTokenMissingKid
	}

	kidStr, ok := kid.(string)
	if !ok {
		return nil, ErrFailedParsingKid
	}

	i.mu.RLock()
	key, ok := i.keys[kidStr]
	i.mu.RUnlock()

	if !ok {
		return nil, ErrUnknownSigningKey
	}

	return key, nil
}

// selectInitialKeyLocked selects the initial signing key based on the desired key ID or the
// most recent ULID key; callers must hold the write lock
func (i *Issuer) selectInitialKeyLocked(loaded []loadedKey, desired string) {
	if desired != "" {
		if signer, ok := i.signingKeys[desired]; ok {
			i.currentKeyID = desired
			i.currentKey = signer
			i.currentSigningMethod = signingMethodForKey(signer)

			return
		}
	}

	var chosen string

	var chosenULID ulid.ULID

	var hasULID bool

	for _, info := range loaded {
		if info.hasULID {
			if !hasULID || info.ulid.Time() > chosenULID.Time() {
				chosen = info.kid
				chosenULID = info.ulid
				hasULID = true
			}
		}
	}

	if !hasULID && len(loaded) > 0 {
		chosen = loaded[len(loaded)-1].kid
	}

	if chosen != "" {
		i.currentKeyID = chosen
		i.currentKey = i.signingKeys[chosen]
		i.currentSigningMethod = signingMethodForKey(i.signingKeys[chosen])
		i.conf.KID = chosen
	}
}

// genKeyID generates a new ULID to use as a key ID
func (i *Issuer) genKeyID() (ulid.ULID, error) {
	ms := ulid.Timestamp(time.Now())

	uid, err := ulid.New(ms, i.kidEntropy)
	if err != nil {
		return uid, fmt.Errorf("could not generate key id: %w", err)
	}

	return uid, nil
}

// signingMethodForKey detects the signing method from a crypto.Signer using jwx
func signingMethodForKey(signer crypto.Signer) jwt.SigningMethod {
	return signingMethodForPublicKey(signer.Public())
}

// signingMethodForPublicKey detects the signing method from a public key using jwx
func signingMethodForPublicKey(publicKey crypto.PublicKey) jwt.SigningMethod {
	key, err := jwk.Import(publicKey)
	if err != nil {
		return jwt.SigningMethodEdDSA
	}

	// Check if algorithm is already set
	alg, ok := key.Algorithm()
	if ok {
		// Map to golang-jwt signing method
		switch alg.String() {
		case "RS256":
			return jwt.SigningMethodRS256
		case "RS384":
			return jwt.SigningMethodRS384
		case "RS512":
			return jwt.SigningMethodRS512
		case "EdDSA":
			return jwt.SigningMethodEdDSA
		default:
			return jwt.SigningMethodEdDSA
		}
	}

	// If no algorithm set, infer from key type
	switch key.KeyType().String() {
	case "RSA":
		return jwt.SigningMethodRS256 // Default to RS256 for RSA keys
	case "OKP":
		return jwt.SigningMethodEdDSA // Ed25519 uses EdDSA
	default:
		return jwt.SigningMethodEdDSA
	}
}
