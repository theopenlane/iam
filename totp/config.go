package totp

import "time"

const (
	defaultLength             = 6
	defaultRecoveryCodeCount  = 16
	defaultRecoveryCodeLength = 8
	codePeriod                = 30
)

type Config struct {
	// Enabled is a flag to enable or disable the OTP service
	Enabled bool `json:"enabled" koanf:"enabled" default:"true"`
	// CodeLength is the length of the OTP code
	CodeLength int `json:"codelength" koanf:"codelength" default:"6"`
	// Issuer is the issuer for TOTP codes
	Issuer string `json:"issuer" koanf:"issuer" domain:"inherit"`
	// WithRedis configures the service with a redis client
	WithRedis bool `json:"redis" koanf:"redis" default:"true"`
	// Secret stores a versioned secret key for cryptography functions
	Secret string `json:"secret" koanf:"secret" sensitive:"true"`
	// RecoveryCodeCount is the number of recovery codes to generate
	RecoveryCodeCount int `json:"recoverycodecount" koanf:"recoverycodecount" default:"16"`
	// RecoveryCodeLength is the length of a recovery code
	RecoveryCodeLength int `json:"recoverycodelength" koanf:"recoverycodelength" default:"8"`
	// MaxFailedAttempts is the number of failed TOTP codes allowed per user within the failure window
	MaxFailedAttempts int `json:"maxfailedattempts" koanf:"maxfailedattempts" default:"5"`
	// FailureWindow is how long failed TOTP attempts are counted before the counter resets
	FailureWindow time.Duration `json:"failurewindow" koanf:"failurewindow" default:"15m"`
}

// NewOTP returns a new OTP validator
func NewOTP(options ...ConfigOption) Manager {
	s := OTP{
		codeLength:         defaultLength,
		ttl:                codePeriod,
		recoveryCodeCount:  defaultRecoveryCodeCount,
		recoveryCodeLength: defaultRecoveryCodeLength,
		maxFailedAttempts:  defaultMaxFailedAttempts,
		failureWindow:      defaultFailureWindow,
	}

	for _, opt := range options {
		opt(&s)
	}

	return &s
}

// ConfigOption configures the validator
type ConfigOption func(*OTP)

// WithCodeLength configures the service with a length for random code generation
func WithCodeLength(length int) ConfigOption {
	return func(s *OTP) {
		s.codeLength = length
	}
}

// WithIssuer configures the service with a TOTP issuing domain
func WithIssuer(issuer string) ConfigOption {
	return func(s *OTP) {
		s.issuer = issuer
	}
}

// WithRecoveryCodeCount configures the service with a number of recovery codes to generate
func WithRecoveryCodeCount(count int) ConfigOption {
	return func(s *OTP) {
		s.recoveryCodeCount = count
	}
}

// WithRecoveryCodeLength configures the service with the length of recovery codes to generate
func WithRecoveryCodeLength(length int) ConfigOption {
	return func(s *OTP) {
		s.recoveryCodeLength = length
	}
}

// WithMaxFailedAttempts configures the service with the number of failed TOTP codes allowed per user within the failure window; non-positive values keep the default
func WithMaxFailedAttempts(count int) ConfigOption {
	return func(s *OTP) {
		if count > 0 {
			s.maxFailedAttempts = count
		}
	}
}

// WithFailureWindow configures the service with how long failed TOTP attempts are counted; non-positive values keep the default
func WithFailureWindow(window time.Duration) ConfigOption {
	return func(s *OTP) {
		if window > 0 {
			s.failureWindow = window
		}
	}
}

// WithSecret sets a new versioned Secret on the client
func WithSecret(x Secret) ConfigOption {
	return func(s *OTP) {
		s.secrets = append(s.secrets, x)
	}
}

// WithRedis configures the service with a redis client
func WithRedis(db otpRedis) ConfigOption {
	return func(s *OTP) {
		s.db = db
	}
}
