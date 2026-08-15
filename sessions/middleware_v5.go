package sessions

import (
	echo "github.com/labstack/echo/v5"
)

// Middleware returns echo v5 middleware that loads the session presented on the request, verifies
// it against the persistent store, and refreshes the session cookie before the response is written.
// A non-nil skipper short-circuits the middleware when it returns true
func Middleware(config SessionConfig, skipper func(c *echo.Context) bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if skipper != nil && skipper(c) {
				return next(c)
			}

			session, userID, err := config.requestSession(c.Request())
			if err != nil {
				return unauthorized(c, err)
			}

			// add session to context to be used in request paths
			ctx := session.addSessionDataToContext(c.Request().Context())
			c.SetRequest(c.Request().WithContext(ctx))

			res, err := echo.UnwrapResponse(c.Response())
			if err != nil {
				return err
			}

			res.Before(func() {
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
