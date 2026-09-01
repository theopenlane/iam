package sessions

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"
	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/echox/middleware"
	"github.com/theopenlane/logx"
	"github.com/theopenlane/utils/rout"
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
}

// Option allows users to optionally supply configuration to the session middleware.
type Option func(opts *SessionConfig)

// NewSessionConfig creates a new session config with options
func NewSessionConfig(sm Store[map[string]any], opts ...Option) (c SessionConfig) {
	c = SessionConfig{
		Skipper:        middleware.DefaultSkipper, // default skipper always returns false
		SessionManager: sm,                        // session manager should always be provided
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

	session.Set(sessionID, sessionMap)

	// Add session to context
	c := session.addSessionDataToContext(ctx)

	if err := session.Save(w); err != nil {
		return c, err
	}

	ttl := time.Duration(sc.CookieConfig.MaxAge * int(time.Second))
	if err := sc.RedisStore.StoreSessionWithExpiration(c, sessionID, userID, ttl); err != nil {
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

			session, userID, err := config.requestSession(c.Request())
			if err != nil {
				return unauthorized(c, err)
			}

			// Add session to context to be used in request paths
			ctx := session.addSessionDataToContext(c.Request().Context())
			c.SetRequest(c.Request().WithContext(ctx))

			c.Response().Before(func() {
				refreshed, ok := config.writeRefreshedSession(c.Request().Context(), c.Response(), userID)
				if !ok {
					return
				}

				c.SetRequest(c.Request().WithContext(refreshed))
			})

			return next(c)
		}
	}
}

// requestSession resolves the session presented on the request and verifies it against the
// persistent store, returning the session and the user id the store holds for it
func (sc *SessionConfig) requestSession(r *http.Request) (*Session[map[string]any], string, error) {
	// get session from request cookies
	session, err := sc.SessionManager.Get(r, sc.CookieConfig.Name)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			logx.FromContext(r.Context()).Debug().Err(err).Msg("no session cookie on request")
		default:
			logx.FromContext(r.Context()).Error().Err(err).Msg("unable to get session")
		}

		return nil, "", ErrInvalidSession
	}

	// get the session id from the session data
	sessionID := sc.SessionManager.GetSessionIDFromCookie(session)
	sessionData := sc.SessionManager.GetSessionDataFromCookie(session)

	// check session token on request matches cache
	userIDFromCookie := sessionData.(map[string]any)[UserIDKey]

	// lookup userID in cache to ensure tokens match
	userID, err := sc.RedisStore.GetSession(r.Context(), sessionID)
	if err != nil {
		logx.FromContext(r.Context()).Error().Err(err).Msg("unable to get session from store")

		return nil, "", ErrInvalidSession
	}

	if userIDFromCookie != userID {
		logx.FromContext(r.Context()).Error().Interface("cookie", userIDFromCookie).Str("store", userID).Msg("sessions do not match")

		return nil, "", ErrInvalidSession
	}

	return session, userID, nil
}

// writeRefreshedSession refreshes and saves the session cookie and store entry unless the request
// context is already cancelled, returning the refreshed context and whether a refresh occurred
func (sc *SessionConfig) writeRefreshedSession(ctx context.Context, w http.ResponseWriter, userID string) (context.Context, bool) {
	// do not write session/cookie if context is cancelled
	select {
	case <-ctx.Done():
		logx.FromContext(ctx).Debug().Msg("request context cancelled, skipping session save")

		return ctx, false
	default:
		// context is still active, proceed to write session/cookie
	}

	// refresh and save session cookie
	refreshed, err := sc.CreateAndStoreSession(ctx, w, userID)
	if err != nil {
		logx.FromContext(ctx).Error().Err(err).Msg("unable to create and store new session")

		panic(err)
	}

	addHeaderIfMissing(w, "Cache-Control", `no-cache="Set-Cookie"`)
	addHeaderIfMissing(w, "Vary", "Cookie")

	return refreshed, true
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
