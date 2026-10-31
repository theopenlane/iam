package sessions

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/echox/middleware"
	"github.com/theopenlane/logx"
	"github.com/theopenlane/utils/rout"
)

const (
	defaultAbsoluteTimeout = 24 * time.Hour
	defaultRenewalInterval = 15 * time.Minute
	defaultRenewalGrace    = 30 * time.Second
)

// SessionConfig is used to configure session management
type SessionConfig struct {
	// Skipper is a function that determines whether a particular request should be skipped or not
	Skipper middleware.Skipper
	// BeforeFunc  defines a function which is executed just before the middleware
	BeforeFunc middleware.BeforeFunc
	// SessionManager is responsible for managing the session cookies. It handles the creation, retrieval, and deletion of
	// session cookies for each user session
	SessionManager Store[map[string]any]
	// CookieConfig contains the cookie settings for sessions
	CookieConfig *CookieConfig
	// RedisStore is used to store and retrieve session data in a persistent manner such as to a redis backend
	RedisStore PersistentStore
	// RedisClient establishes a connection to a Redis server and perform operations such as storing and retrieving data
	RedisClient *redis.Client
	// FallbackUserID resolves the user to mint a session for when the request carries no valid one
	FallbackUserID func(ctx context.Context) (string, bool)
	// AbsoluteTimeout is the maximum session lifetime from first authentication regardless of activity
	AbsoluteTimeout time.Duration
	// RenewalInterval is how often the session id is reissued while the session stays active
	RenewalInterval time.Duration
	// RenewalGrace is how long a superseded session id stays valid so in-flight requests still succeed
	RenewalGrace time.Duration
}

// Option allows users to optionally supply configuration to the session middleware.
type Option func(opts *SessionConfig)

// NewSessionConfig creates a new session config with options
func NewSessionConfig(sm Store[map[string]any], opts ...Option) (c SessionConfig) {
	c = SessionConfig{
		Skipper:        middleware.DefaultSkipper, // default skipper always returns false
		SessionManager: sm,                        // session manager should always be provided

		AbsoluteTimeout: defaultAbsoluteTimeout,
		RenewalInterval: defaultRenewalInterval,
		RenewalGrace:    defaultRenewalGrace,
	}

	for _, opt := range opts {
		opt(&c)
	}

	if c.RedisClient != nil {
		c.RedisStore = NewStore(c.RedisClient)
	}

	return c
}

// WithPersistence allows the user to specify a redis client for the middleware to persist sessions
func WithPersistence(client *redis.Client) Option {
	return func(opts *SessionConfig) {
		opts.RedisClient = client
	}
}

// WithSkipperFunc allows the user to specify a skipper function for the middleware
func WithSkipperFunc(skipper middleware.Skipper) Option {
	return func(opts *SessionConfig) {
		opts.Skipper = skipper
	}
}

// WithBeforeFunc allows the user to specify a function to happen before the middleware
func WithBeforeFunc(before middleware.BeforeFunc) Option {
	return func(opts *SessionConfig) {
		opts.BeforeFunc = before
	}
}

// WithFallbackUserID sets the resolver used to mint a session when the request carries no valid one
func WithFallbackUserID(resolve func(ctx context.Context) (string, bool)) Option {
	return func(opts *SessionConfig) {
		opts.FallbackUserID = resolve
	}
}

// WithMaxAge allows the user to specify the maximum age for the session cookie, defaults to 3600 seconds (1 hour)
func WithMaxAge(maxAge int) Option {
	return func(opts *SessionConfig) {
		if opts.CookieConfig == nil {
			opts.CookieConfig = &CookieConfig{}
		}

		// Set the MaxAge for the cookie configuration
		opts.CookieConfig.MaxAge = maxAge
	}
}

// WithAbsoluteTimeout sets the maximum session lifetime from first authentication, defaults to 24 hours
func WithAbsoluteTimeout(d time.Duration) Option {
	return func(opts *SessionConfig) {
		opts.AbsoluteTimeout = d
	}
}

// WithRenewalInterval sets how often the session id is reissued while active, defaults to 15 minutes
func WithRenewalInterval(d time.Duration) Option {
	return func(opts *SessionConfig) {
		opts.RenewalInterval = d
	}
}

// WithRenewalGrace sets how long a superseded session id stays valid, defaults to 30 seconds
func WithRenewalGrace(d time.Duration) Option {
	return func(opts *SessionConfig) {
		opts.RenewalGrace = d
	}
}

// CreateAndStoreSession creates the session values with user ID and sets the cookie stores the session in
// the persistent store (redis)
func (sc *SessionConfig) CreateAndStoreSession(ctx context.Context, w http.ResponseWriter, userID string) (context.Context, error) {
	setSessionMap := map[string]any{}
	setSessionMap[UserIDKey] = userID

	return sc.SaveAndStoreSession(ctx, w, setSessionMap, userID)
}

// SaveAndStoreSession saves the session to the cookie and to the persistent store (redis) with the provided map of values
func (sc *SessionConfig) SaveAndStoreSession(ctx context.Context, w http.ResponseWriter, sessionMap map[string]any, userID string) (context.Context, error) {
	session := sc.SessionManager.New(sc.CookieConfig.Name)
	sessionID := GenerateSessionID()
	now := time.Now()

	sessionMap[RenewedAtKey] = now.Unix()

	createdAt, ok := unixFromSessionData(sessionMap, CreatedAtKey)
	if !ok {
		createdAt = now
		sessionMap[CreatedAtKey] = now.Unix()
	}

	session.Set(sessionID, sessionMap)

	// Add session to context
	c := session.addSessionDataToContext(ctx)

	if err := sc.RedisStore.StoreSessionWithExpiration(c, sessionID, userID, sc.sessionTTL(createdAt, now)); err != nil {
		return c, err
	}

	if err := session.Save(w); err != nil {
		return c, err
	}

	return c, nil
}

// DestroySession is the inverse of CreateAndStoreSession: it removes the session presented on the
// request by deleting the persisted session from the backing store (e.g. redis) and expiring the
// session cookie on the response. This is the correct way to invalidate a session on logout, since
// the cookie-only Store.Destroy and Session.Destroy leave the persisted session in place.
//
// A request that carries no resolvable session is treated as already destroyed: the cookie is still
// expired and nil is returned, which keeps logout idempotent. A cookie that is present but cannot be
// decoded is anomalous (tampering, corruption, or a dropped signing key); it cannot identify a
// persisted session to delete, so it is logged and the bad cookie is cleared, but it is not treated
// as a hard failure since it is not retryable and decode errors can occur benignly during key
// rotation. An error is only returned when an identified, persisted session could not be deleted, so
// callers can avoid reporting a logout that did not take effect
func (sc *SessionConfig) DestroySession(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	session, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
	if err != nil {
		// a missing cookie is normal; a cookie that is present but undecodable is anomalous and logged
		if !errors.Is(err, http.ErrNoCookie) {
			logx.FromContext(ctx).Warn().Err(err).Msg("could not decode session cookie on destroy; clearing it")
		}

		// no resolvable session to remove server-side, but still expire whatever cookie was presented
		RemoveCookie(w, sc.CookieConfig.Name, *sc.CookieConfig)

		return nil
	}

	if sessionID := sc.SessionManager.GetSessionIDFromCookie(session); sessionID != "" && sc.RedisStore != nil {
		if err := sc.RedisStore.DeleteSession(ctx, sessionID); err != nil {
			return err
		}
	}

	RemoveCookie(w, sc.CookieConfig.Name, *sc.CookieConfig)

	return nil
}

// LoadAndSave is a middleware function that loads and saves session data using a
// provided session manager. It takes a `SessionManager` as input and returns a middleware function
// that can be used with an Echo framework application
func LoadAndSave(sm Store[map[string]any], opts ...Option) echo.MiddlewareFunc {
	c := NewSessionConfig(sm, opts...)

	return LoadAndSaveWithConfig(c)
}

// LoadAndSaveWithConfig is a middleware that loads and saves session data
// using a provided session manager configuration
// It takes a `SessionConfig` struct as input, which contains the skipper function and the session manager
func LoadAndSaveWithConfig(config SessionConfig) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = middleware.DefaultSkipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// if skipper function returns true, skip this middleware
			if config.Skipper(c) {
				return next(c)
			}

			// execute any before functions
			if config.BeforeFunc != nil {
				config.BeforeFunc(c)
			}

			loaded, err := config.loadSession(c.Request().Context(), c.Response(), c.Request())
			if err != nil {
				return unauthorized(c, err)
			}

			// Add session to context to be used in request paths
			c.SetRequest(c.Request().WithContext(loaded.ctx))

			if !loaded.created {
				c.Response().Before(func() {
					refreshed, ok := config.writeRefreshedSession(c.Request().Context(), c.Response(), loaded)
					if !ok {
						return
					}

					c.SetRequest(c.Request().WithContext(refreshed))
				})
			}

			return next(c)
		}
	}
}

// loadedSession is a resolved session, how it was presented, and whether it was minted on this request
type loadedSession struct {
	ctx       context.Context
	session   *Session[map[string]any]
	values    map[string]any
	userID    string
	sessionID string
	createdAt time.Time
	renewedAt time.Time
	created   bool
}

// sessionTTL is the shorter of the idle max age and the time left before the absolute timeout
func (sc *SessionConfig) sessionTTL(createdAt, now time.Time) time.Duration {
	return min(time.Duration(sc.CookieConfig.MaxAge)*time.Second, sc.AbsoluteTimeout-now.Sub(createdAt))
}

// unixFromSessionData reads an int64 unix seconds value from the session data
func unixFromSessionData(data map[string]any, key string) (time.Time, bool) {
	secs, ok := data[key].(int64)
	if !ok {
		return time.Time{}, false
	}

	return time.Unix(secs, 0), true
}

// loadSession resolves the session on the request, minting one via FallbackUserID when it is invalid
func (sc *SessionConfig) loadSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (loadedSession, error) {
	loaded, err := sc.requestSession(r)
	if err == nil {
		loaded.ctx = loaded.session.addSessionDataToContext(ctx)

		return loaded, nil
	}

	if sc.FallbackUserID == nil {
		return loadedSession{}, err
	}

	fallbackUserID, ok := sc.FallbackUserID(ctx)
	if !ok || fallbackUserID == "" {
		return loadedSession{}, err
	}

	logx.FromContext(ctx).Debug().Str("user_id", fallbackUserID).Msg("no valid session on request, creating one for the authenticated caller")

	created, err := sc.CreateAndStoreSession(ctx, w, fallbackUserID)
	if err != nil {
		logx.FromContext(ctx).Error().Err(err).Msg("unable to create session for the authenticated caller")

		return loadedSession{}, ErrInvalidSession
	}

	markSessionCookieResponse(w)

	return loadedSession{ctx: created, userID: fallbackUserID, created: true}, nil
}

// requestSession resolves the session presented on the request and verifies it against the
// persistent store and its absolute lifetime, returning the resolved session without ctx set
func (sc *SessionConfig) requestSession(r *http.Request) (loadedSession, error) {
	// get session from request cookies
	session, err := sc.SessionManager.Get(r, sc.CookieConfig.Name)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			logx.FromContext(r.Context()).Debug().Err(err).Msg("no session cookie on request")
		default:
			logx.FromContext(r.Context()).Error().Err(err).Msg("unable to get session")
		}

		return loadedSession{}, ErrInvalidSession
	}

	// get the session id from the session data
	sessionID := sc.SessionManager.GetSessionIDFromCookie(session)
	values := sc.SessionManager.GetSessionDataFromCookie(session).(map[string]any)

	// check session token on request matches cache
	userIDFromCookie := values[UserIDKey]

	// lookup userID in cache to ensure tokens match
	userID, err := sc.RedisStore.GetSession(r.Context(), sessionID)
	if err != nil {
		logx.FromContext(r.Context()).Error().Err(err).Msg("unable to get session from store")

		return loadedSession{}, ErrInvalidSession
	}

	if userIDFromCookie != userID {
		logx.FromContext(r.Context()).Error().Interface("cookie", userIDFromCookie).Str("store", userID).Msg("sessions do not match")

		return loadedSession{}, ErrInvalidSession
	}

	// a missing created time (legacy cookie) is treated as expired
	createdAt, ok := unixFromSessionData(values, CreatedAtKey)
	now := time.Now()

	if !ok || now.Sub(createdAt) >= sc.AbsoluteTimeout {
		if err := sc.RedisStore.DeleteSession(r.Context(), sessionID); err != nil {
			logx.FromContext(r.Context()).Error().Err(err).Msg("unable to delete expired session")
		}

		logx.FromContext(r.Context()).Debug().Msg("session reached its absolute lifetime")

		return loadedSession{}, ErrSessionExpired
	}

	renewedAt, _ := unixFromSessionData(values, RenewedAtKey)

	return loadedSession{
		session:   session,
		values:    values,
		userID:    userID,
		sessionID: sessionID,
		createdAt: createdAt,
		renewedAt: renewedAt,
	}, nil
}

// writeRefreshedSession slides the idle deadline of the presented session and reissues its id once the renewal
// interval has elapsed; it is skipped when the context is cancelled or the handler already set the session cookie
func (sc *SessionConfig) writeRefreshedSession(ctx context.Context, w http.ResponseWriter, loaded loadedSession) (context.Context, bool) {
	// do not write session/cookie if context is cancelled
	select {
	case <-ctx.Done():
		logx.FromContext(ctx).Debug().Msg("request context cancelled, skipping session save")

		return ctx, false
	default:
		// context is still active, proceed to write session/cookie
	}

	if responseSetsCookie(w, sc.CookieConfig.Name) {
		logx.FromContext(ctx).Debug().Msg("handler already set the session cookie, skipping session refresh")

		return ctx, false
	}

	now := time.Now()

	if now.Sub(loaded.renewedAt) < sc.RenewalInterval {
		if err := sc.RedisStore.StoreSessionWithExpiration(ctx, loaded.sessionID, loaded.userID, sc.sessionTTL(loaded.createdAt, now)); err != nil {
			logx.FromContext(ctx).Error().Err(err).Msg("unable to extend session idle deadline")

			return ctx, false
		}

		if err := sc.SessionManager.Save(w, loaded.session); err != nil {
			logx.FromContext(ctx).Error().Err(err).Msg("unable to resend session cookie")

			return ctx, false
		}

		markSessionCookieResponse(w)

		return ctx, false
	}

	refreshed, err := sc.SaveAndStoreSession(ctx, w, maps.Clone(loaded.values), loaded.userID)
	if err != nil {
		logx.FromContext(ctx).Error().Err(err).Msg("unable to create and store new session")

		panic(err)
	}

	// the superseded id stays valid only for in-flight requests, not for the remainder of its original ttl
	if err := sc.RedisStore.StoreSessionWithExpiration(ctx, loaded.sessionID, loaded.userID, sc.RenewalGrace); err != nil {
		logx.FromContext(ctx).Error().Err(err).Msg("unable to retire superseded session")
	}

	markSessionCookieResponse(w)

	return refreshed, true
}

// responseSetsCookie reports whether the response already carries a Set-Cookie header for the named cookie
func responseSetsCookie(w http.ResponseWriter, name string) bool {
	return lo.SomeBy(w.Header().Values("Set-Cookie"), func(v string) bool {
		return strings.HasPrefix(v, name+"=")
	})
}

// markSessionCookieResponse adds the headers that keep a response carrying a session cookie out of shared caches
func markSessionCookieResponse(w http.ResponseWriter) {
	addHeaderIfMissing(w, "Cache-Control", `no-cache="Set-Cookie"`)
	addHeaderIfMissing(w, "Vary", "Cookie")
}

// addHeaderIfMissing function is used to add a header to the HTTP response if it is not already
// present. It takes in the response writer (`http.ResponseWriter`), the header key, and the header
// value as parameters
func addHeaderIfMissing(w http.ResponseWriter, key, value string) {
	if slices.Contains(w.Header()[key], value) {
		return
	}

	w.Header().Add(key, value)
}

// jsonWriter is satisfied by both echo context flavors so the unauthorized reply is written once
type jsonWriter interface {
	JSON(code int, i any) error
}

// unauthorized returns a 401 Unauthorized response with the error message.
func unauthorized(c jsonWriter, err error) error {
	if err := c.JSON(http.StatusUnauthorized, rout.ErrorResponse(err)); err != nil {
		return err
	}

	return err
}
