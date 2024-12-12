package sessions

import (
	"context"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/echox/middleware"
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

// CreateAndStoreSession creates the session values with user ID and sets the cookie stores the session in
// the persistent store (redis)
func (sc *SessionConfig) CreateAndStoreSession(ctx echo.Context, userID string) error {
	setSessionMap := map[string]any{}
	setSessionMap[UserIDKey] = userID

	c, err := sc.SaveAndStoreSession(ctx.Request().Context(), ctx.Response().Writer, setSessionMap, userID)
	if err != nil {
		return err
	}

	ctx.SetRequest(ctx.Request().WithContext(c))

	return nil
}

// SaveAndStoreSession saves the session to the cookie and to the persistent store (redis) with the provided map of values
func (sc *SessionConfig) SaveAndStoreSession(ctx context.Context, w http.ResponseWriter, sessionMap map[string]any, userID string) (context.Context, error) {
	session := sc.SessionManager.New(sc.CookieConfig.Name)
	sessionID := GenerateSessionID()

	session.Set(sessionID, sessionMap)

	// Add session to context
	c := session.newAddSessionDataToContext(ctx)

	if err := session.Save(w); err != nil {
		return c, err
	}

	ttl := time.Duration(sc.CookieConfig.MaxAge * int(time.Second))
	if err := sc.RedisStore.StoreSessionWithExpiration(c, sessionID, userID, ttl); err != nil {
		return c, err
	}

	return c, nil
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

			// get session from request cookies
			session, err := config.SessionManager.Get(c.Request(), config.CookieConfig.Name)
			if err != nil {
				log.Error().Err(err).Msg("unable to get session")

				return err
			}

			// get the session id from the session data
			sessionID := config.SessionManager.GetSessionIDFromCookie(session)
			sessionData := config.SessionManager.GetSessionDataFromCookie(session)

			// check session token on request matches cache
			userIDFromCookie := sessionData.(map[string]any)[UserIDKey]

			// lookup userID in cache to ensure tokens match
			userID, err := config.RedisStore.GetSession(c.Request().Context(), sessionID)
			if err != nil {
				log.Error().Err(err).Msg("unable to get session from store")

				return err
			}

			if userIDFromCookie != userID {
				log.Error().
					Err(err).
					Interface("cookie", userIDFromCookie).
					Str("store", userID).
					Msg("sessions do not match")

				return err
			}

			// Add session to context to be used in request paths
			ctx := session.newAddSessionDataToContext(c.Request().Context())
			c.SetRequest(c.Request().WithContext(ctx))

			c.Response().Before(func() {
				// refresh and save session cookie
				if err := config.CreateAndStoreSession(c, sessionID); err != nil {
					log.Error().Err(err).Msg("unable to create and store new session")

					panic(err)
				}

				addHeaderIfMissing(c.Response(), "Cache-Control", `no-cache="Set-Cookie"`)
				addHeaderIfMissing(c.Response(), "Vary", "Cookie")
			})

			return next(c)
		}
	}
}

// addHeaderIfMissing function is used to add a header to the HTTP response if it is not already
// present. It takes in the response writer (`http.ResponseWriter`), the header key, and the header
// value as parameters
func addHeaderIfMissing(w http.ResponseWriter, key, value string) {
	for _, h := range w.Header()[key] {
		if h == value {
			return
		}
	}

	w.Header().Add(key, value)
}
