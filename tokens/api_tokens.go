package tokens

import (
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/oklog/ulid/v2"
	"github.com/theopenlane/utils/ulids"
)

const (
	// apiTokenSecretSize controls the number of random bytes embedded in the opaque token.
	apiTokenSecretSize = 32
	// tokenSegments represents the number of segments when splitting an opaque token.
	tokenSegments = 2
	// envSplitParts represents the number of segments when splitting an environment key pair.
	envSplitParts = 2
	// statusSecretDelimiter separates the optional status and secret components in environment variables.
	statusSecretDelimiter = ":"
)

const (
	// wrappedErrorFormat is the shared format string for wrapping underlying errors.
	wrappedErrorFormat = "%w: %v"
	// keyWrappedErrorFormat is the shared format string when annotating key-related errors.
	keyWrappedErrorFormat = "api token key %s: %w"
)

var (
	opaqueEncoding = base64.RawURLEncoding
)

// APITokenKey describes the symmetric key material used to hash opaque tokens
type APITokenKey struct {
	Version string
	Secret  []byte
	Status  KeyStatus
}

// validateKeyMaterial ensures the provided key contains the minimum required fields.
func validateKeyMaterial(key APITokenKey) error {
	if key.Version == "" {
		return ErrAPITokenMissingKeyVersion
	}

	if len(key.Secret) == 0 {
		return ErrAPITokenSecretMissing
	}

	return nil
}

// initialKeyStatus determines the status for a key when constructing a new keyring.
func initialKeyStatus(status KeyStatus, assignActive bool) KeyStatus {
	if status != "" {
		return status
	}

	if assignActive {
		return KeyStatusActive
	}

	return KeyStatusDeprecated
}

// upsertKeyStatus determines the status for a key during an upsert operation.
func upsertKeyStatus(status KeyStatus) KeyStatus {
	if status != "" {
		return status
	}

	return KeyStatusDeprecated
}

// cloneSecretBytes returns a defensive copy of the provided secret.
func cloneSecretBytes(secret []byte) []byte {
	if len(secret) == 0 {
		return nil
	}

	cloned := make([]byte, len(secret))
	copy(cloned, secret)

	return cloned
}

// ensureSingleActiveKey verifies that exactly one active key exists when building a new keyring.
func ensureSingleActiveKey(count int) error {
	if count == 0 {
		return ErrAPITokenNoActiveKey
	}

	if count > 1 {
		return ErrAPITokenMultipleActiveKeys
	}

	return nil
}

// clone creates a deep copy of the API token key to prevent external mutation of stored key material
func (k *APITokenKey) clone() *APITokenKey {
	if k == nil {
		return nil
	}

	cloned := &APITokenKey{
		Version: k.Version,
		Status:  k.Status,
	}

	if len(k.Secret) > 0 {
		cloned.Secret = make([]byte, len(k.Secret))
		copy(cloned.Secret, k.Secret)
	}

	return cloned
}

// APITokenKeyring retains the active and historical key material used to hash opaque API tokens
// The keyring enforces that exactly one key is active at any given time, while allowing deprecated
// keys to remain available for verification during rotation
type APITokenKeyring struct {
	mu            sync.RWMutex
	keys          map[string]*APITokenKey
	activeVersion string
}

// NewAPITokenKeyring constructs an API token keyring from the provided key definitions
// At least one key must be supplied - if a key omits a Status, the first key defaults to
// active and subsequent keys default to deprecated
func NewAPITokenKeyring(keys ...APITokenKey) (*APITokenKeyring, error) {
	if len(keys) == 0 {
		return nil, ErrAPITokenNoActiveKey
	}

	kr := &APITokenKeyring{
		keys: make(map[string]*APITokenKey, len(keys)),
	}

	activeCount := 0

	for i := range keys {
		key := keys[i]

		if err := validateKeyMaterial(key); err != nil {
			return nil, err
		}

		if _, exists := kr.keys[key.Version]; exists {
			return nil, ErrAPITokenDuplicateKeyVersion
		}

		key.Status = initialKeyStatus(key.Status, activeCount == 0)
		if key.Status == KeyStatusActive {
			activeCount++
			kr.activeVersion = key.Version
		}

		kr.keys[key.Version] = key.clone()
	}

	return kr, ensureSingleActiveKey(activeCount)
}

// CurrentKey returns the active key material for hashing new opaque tokens
func (kr *APITokenKeyring) CurrentKey() (*APITokenKey, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	return kr.currentKeyLocked()
}

// CurrentVersion returns the key version used for new tokens
func (kr *APITokenKeyring) CurrentVersion() (string, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.activeVersion == "" {
		return "", ErrAPITokenNoActiveKey
	}

	return kr.activeVersion, nil
}

// Get returns the key material associated with a version if it exists and is not revoked
func (kr *APITokenKeyring) Get(version string) (*APITokenKey, error) {
	if version == "" {
		return nil, ErrAPITokenMissingKeyVersion
	}

	kr.mu.RLock()
	defer kr.mu.RUnlock()

	key, ok := kr.keys[version]
	if !ok {
		return nil, ErrAPITokenKeyVersionUnknown
	}

	if key.Status == KeyStatusRevoked {
		return nil, ErrAPITokenKeyRevoked
	}

	return key.clone(), nil
}

// Upsert updates or adds the supplied keys. When a key is marked active, any previously
// active key is automatically deprecated to ensure only one active key remains
func (kr *APITokenKeyring) Upsert(keys ...APITokenKey) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	for i := range keys {
		key := keys[i]

		if err := validateKeyMaterial(key); err != nil {
			return err
		}

		status := upsertKeyStatus(key.Status)
		entry := kr.ensureEntry(key.Version)
		entry.Secret = cloneSecretBytes(key.Secret)
		entry.Status = status

		if status == KeyStatusActive {
			kr.deprecateCurrentActiveLocked(key.Version)
			kr.activeVersion = key.Version
		}
	}

	active, err := kr.currentKeyLocked()
	if err != nil {
		return err
	}

	if active.Status == KeyStatusRevoked {
		return ErrAPITokenKeyRevoked
	}

	return nil
}

// ensureEntry returns the existing key entry or creates a new placeholder for the provided version.
func (kr *APITokenKeyring) ensureEntry(version string) *APITokenKey {
	entry, exists := kr.keys[version]
	if !exists {
		entry = &APITokenKey{Version: version}
		kr.keys[version] = entry
	}

	return entry
}

// deprecateCurrentActiveLocked marks the current active key as deprecated when switching to a new active version.
func (kr *APITokenKeyring) deprecateCurrentActiveLocked(newVersion string) {
	if kr.activeVersion == "" || kr.activeVersion == newVersion {
		return
	}

	if current, exists := kr.keys[kr.activeVersion]; exists && current.Status == KeyStatusActive {
		current.Status = KeyStatusDeprecated
	}
}

func (kr *APITokenKeyring) currentKeyLocked() (*APITokenKey, error) {
	if kr.activeVersion == "" {
		return nil, ErrAPITokenNoActiveKey
	}

	key, ok := kr.keys[kr.activeVersion]
	if !ok {
		return nil, ErrAPITokenNoActiveKey
	}

	if key.Status == KeyStatusRevoked {
		return nil, ErrAPITokenKeyRevoked
	}

	return key.clone(), nil
}

// GeneratedAPIToken contains the opaque token presented to callers together with the
// associated metadata required to persist and validate it in storage
type GeneratedAPIToken struct {
	TokenID      ulid.ULID
	Secret       string
	Value        string
	Hash         string
	KeyVersion   string
	SecretDigest []byte
}

// GenerateAPIToken creates a new opaque API token and returns the token value together with the
// derived hash and metadata required for persistence
func (tm *TokenManager) GenerateAPIToken() (*GeneratedAPIToken, error) {
	if tm.apiTokenKeyring == nil {
		return nil, ErrAPITokenKeyringNotConfigured
	}

	key, err := tm.apiTokenKeyring.CurrentKey()
	if err != nil {
		return nil, err
	}

	secretBytes := make([]byte, apiTokenSecretSize)

	reader := tm.apiTokenEntropy
	if reader == nil {
		reader = cryptoRand.Reader
	}

	if _, err = io.ReadFull(reader, secretBytes); err != nil {
		return nil, fmt.Errorf("generate api token secret: %w", err)
	}

	// ULID IDs keep tokens sortable by creation time which helps with debugging and audit trails
	tokenID := ulids.New()
	secret := opaqueEncoding.EncodeToString(secretBytes)
	// Combine the token identifier and secret into the opaque token representation returned to clients
	value := fmt.Sprintf("%s.%s", tokenID.String(), secret)
	digest := computeAPITokenDigest(key.Secret, tokenID, secretBytes)

	return &GeneratedAPIToken{
		TokenID:      tokenID,
		Secret:       secret,
		Value:        value,
		Hash:         opaqueEncoding.EncodeToString(digest),
		KeyVersion:   key.Version,
		SecretDigest: digest,
	}, nil
}

// GenerateAPITokenKeyMaterial produces a ULID-based key version and random secret for configuration-driven key rotation
// The secret should be persisted in a secure store (usually base64 encoded) and supplied to APITokenConfig
func GenerateAPITokenKeyMaterial() (version string, secret []byte, err error) {
	secret = make([]byte, apiTokenSecretSize)
	if _, err = io.ReadFull(cryptoRand.Reader, secret); err != nil {
		return "", nil, fmt.Errorf("generate api token key material: %w", err)
	}

	// Return a ULID so declarative configs naturally order keys by generation time.
	return ulids.New().String(), secret, nil
}

// VerifyAPIToken checks that the provided opaque token matches the stored hash using the supplied key version
// The token ID is returned on success to simplify downstream lookups
func (tm *TokenManager) VerifyAPIToken(tokenValue string, storedHash string, keyVersion string) (ulid.ULID, error) {
	if tm.apiTokenKeyring == nil {
		return ulid.ULID{}, ErrAPITokenKeyringNotConfigured
	}

	key, err := tm.apiTokenKeyring.Get(keyVersion)
	if err != nil {
		return ulid.ULID{}, err
	}

	// Split the presented token into the ULID identifier and plaintext secret segment
	tokenID, secretBytes, err := parseOpaqueToken(tokenValue)
	if err != nil {
		return ulid.ULID{}, err
	}

	// Stored hashes are base64 encoded for persistence, decode to raw bytes for comparison
	expectedHashBytes, err := opaqueEncoding.DecodeString(storedHash)
	if err != nil {
		return ulid.ULID{}, fmt.Errorf(wrappedErrorFormat, ErrAPITokenHashInvalid, err)
	}

	// Recompute the HMAC using the key version that was active when the token was issued
	computed := computeAPITokenDigest(key.Secret, tokenID, secretBytes)

	if subtle.ConstantTimeCompare(computed, expectedHashBytes) != 1 {
		return ulid.ULID{}, ErrAPITokenVerificationFailed
	}

	return tokenID, nil
}

// HashAPITokenComponents recomputes the stored hash for an existing token using the provided key version.
// This is useful during key rotation where tokens should be rehashed lazily as they are presented.
func (tm *TokenManager) HashAPITokenComponents(tokenID ulid.ULID, secret string, keyVersion string) (string, error) {
	if tm.apiTokenKeyring == nil {
		return "", ErrAPITokenKeyringNotConfigured
	}

	key, err := tm.apiTokenKeyring.Get(keyVersion)
	if err != nil {
		return "", err
	}

	secretBytes, err := opaqueEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf(wrappedErrorFormat, ErrAPITokenInvalidFormat, err)
	}

	// The recomputed digest can replace the persisted hash during lazy rehash operations
	digest := computeAPITokenDigest(key.Secret, tokenID, secretBytes)

	return opaqueEncoding.EncodeToString(digest), nil
}

// computeAPITokenDigest derives the HMAC-SHA256 digest used for storage and verification.
func computeAPITokenDigest(key []byte, tokenID ulid.ULID, secret []byte) []byte {
	// HMAC-SHA256 guards against secret disclosure even if the database leaks.
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(tokenID[:])
	_, _ = mac.Write(secret)

	return mac.Sum(nil)
}

// parseOpaqueToken splits an opaque token string into its ULID identifier and secret payload segments.
func parseOpaqueToken(value string) (ulid.ULID, []byte, error) {
	parts := strings.Split(value, ".")
	if len(parts) != tokenSegments {
		return ulid.ULID{}, nil, ErrAPITokenInvalidFormat
	}

	tokenID, err := ulid.Parse(parts[0])
	if err != nil {
		return ulid.ULID{}, nil, fmt.Errorf(wrappedErrorFormat, ErrAPITokenInvalidFormat, err)
	}

	// The second segment is the base64-encoded secret originally issued to the caller.
	secretBytes, err := opaqueEncoding.DecodeString(parts[1])
	if err != nil {
		return ulid.ULID{}, nil, fmt.Errorf(wrappedErrorFormat, ErrAPITokenInvalidFormat, err)
	}

	return tokenID, secretBytes, nil
}

// splitStatusAndSecret divides the optional status prefix from the secret payload in environment values.
func splitStatusAndSecret(raw string) (string, string) {
	idx := strings.Index(raw, statusSecretDelimiter)
	if idx == -1 {
		return "", raw
	}

	return strings.TrimSpace(raw[:idx]), raw[idx+1:]
}

// parseEnvKey converts a prefixed environment variable into an API token key definition.
func parseEnvKey(prefix, kv string) (APITokenKey, bool, error) {
	if !strings.HasPrefix(kv, prefix) {
		return APITokenKey{}, false, nil
	}

	nameValue := strings.SplitN(kv, "=", envSplitParts)
	if len(nameValue) != envSplitParts {
		return APITokenKey{}, false, nil
	}

	version := strings.TrimPrefix(nameValue[0], prefix)
	if version == "" {
		return APITokenKey{}, false, ErrAPITokenVersionFromEnvMissing
	}

	statusSegment, secretSegment := splitStatusAndSecret(nameValue[1])

	secret, err := decodeAPITokenSecret(secretSegment)
	if err != nil {
		return APITokenKey{}, false, fmt.Errorf(keyWrappedErrorFormat, version, err)
	}

	key := APITokenKey{Version: version, Secret: secret}

	if statusSegment != "" {
		status, err := parseAPITokenStatus(statusSegment)
		if err != nil {
			return APITokenKey{}, false, fmt.Errorf(keyWrappedErrorFormat, version, err)
		}

		key.Status = status
	}

	return key, true, nil
}

// LoadAPITokenKeyringFromEnv constructs an API token keyring from environment variables that share the provided prefix.
// Each matching variable name must follow the pattern <prefix><version>=<status>:<base64-secret>.
// The status segment is optional; when omitted the key defaults to deprecated unless it becomes the first key in the set.
func LoadAPITokenKeyringFromEnv(prefix string) (*APITokenKeyring, error) {
	if prefix == "" {
		return nil, ErrAPITokenEnvPrefixRequired
	}

	environ := os.Environ()
	if len(environ) == 0 {
		return nil, ErrAPITokenNoKeysFound
	}

	var keys []APITokenKey

	for _, kv := range environ {
		key, ok, err := parseEnvKey(prefix, kv)
		if err != nil {
			return nil, err
		}

		if ok {
			keys = append(keys, key)
		}
	}

	if len(keys) == 0 {
		return nil, ErrAPITokenNoKeysFound
	}

	// Sort versions to keep map iteration deterministic
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Version < keys[j].Version
	})

	return NewAPITokenKeyring(keys...)
}

// decodeAPITokenSecret accepts a base64 encoded secret and returns the raw bytes regardless of encoding variant
func decodeAPITokenSecret(value string) ([]byte, error) {
	if value == "" {
		return nil, ErrAPITokenSecretMissing
	}

	decoders := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}

	var lastErr error

	for _, enc := range decoders {
		decoded, err := enc.DecodeString(value)
		if err == nil {
			return decoded, nil
		}

		// Track last error so we can surface the final failure with context if all decoders fail
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf(wrappedErrorFormat, ErrAPITokenSecretInvalid, lastErr)
	}

	return nil, ErrAPITokenSecretInvalid
}

// parseAPITokenStatus converts a string representation of key status into the corresponding KeyStatus type
func parseAPITokenStatus(value string) (KeyStatus, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "active":
		return KeyStatusActive, nil
	case "deprecated":
		return KeyStatusDeprecated, nil
	case "revoked":
		return KeyStatusRevoked, nil
	default:
		// Anything outside of the whitelist is rejected so configuration errors surface immediately at startup
		return "", fmt.Errorf("%w: %s", ErrAPITokenInvalidStatus, value)
	}
}

// NewAPITokenKeyringFromConfig builds an API token keyring using statically configured keys
func NewAPITokenKeyringFromConfig(cfg APITokenConfig) (*APITokenKeyring, error) {
	if len(cfg.Keys) == 0 {
		return nil, ErrAPITokenNoKeysFound
	}

	versions := make([]string, 0, len(cfg.Keys))
	for version := range cfg.Keys {
		versions = append(versions, version)
	}

	// Sort keys to ensure deterministic ordering even though maps iterate randomly
	sort.Strings(versions)

	keys := make([]APITokenKey, 0, len(versions))

	for _, version := range versions {
		entry := cfg.Keys[version]

		if version == "" {
			return nil, ErrAPITokenMissingKeyVersion
		}

		secret, err := decodeAPITokenSecret(entry.Secret)
		if err != nil {
			return nil, fmt.Errorf(keyWrappedErrorFormat, version, err)
		}

		status, err := parseAPITokenStatus(entry.Status)
		if err != nil {
			return nil, fmt.Errorf(keyWrappedErrorFormat, version, err)
		}

		keys = append(keys, APITokenKey{
			Version: version,
			Secret:  secret,
			Status:  status,
		})
	}

	return NewAPITokenKeyring(keys...)
}

// loadAPITokenKeyringFromConfig chooses the appropriate loader based on whether static keys were supplied
func loadAPITokenKeyringFromConfig(cfg APITokenConfig) (*APITokenKeyring, error) {
	if len(cfg.Keys) > 0 {
		return NewAPITokenKeyringFromConfig(cfg)
	}

	prefix := cfg.EnvPrefix
	if prefix == "" {
		prefix = DefaultAPITokenEnvPrefix
	}

	// Fall back to environment loading when static configuration is absent
	return LoadAPITokenKeyringFromEnv(prefix)
}
