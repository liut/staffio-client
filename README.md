Staffio client and general OAuth2 client
===

## Features

- **OAuth2 Authorization Code Flow** - Full OAuth2 authentication with Staffio identity provider
- **Session Management** - Cookie-based sessions with configurable name/path/domain
- **Role-Based Access Control** - Role verification during authentication callbacks
- **Token Refresh** - Automatic token refresh support
- **Multiple Auth Mechanisms** - Cookie, Header, or middleware-based authentication
- **User Info Extraction** - Extract user from token response with priority handling (Me > User)
- **CSRF Protection** - State token management for OAuth security
- **Flexible Configuration** - Environment variables or runtime configuration
- **AJAX Support** - Detects AJAX requests and returns appropriate responses

## Environment Variables

```sh
# Required
OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=
OAUTH_PREFIX=https://staffio.work       # Staffio service URL

# Optional
OAUTH_URI_AUTHORIZE=/authorize
OAUTH_URI_TOKEN=/token
OAUTH_URI_INFO=/info/me
OAUTH_REDIRECT_URL=/auth/callback
OAUTH_SCOPES=openid
AUTH_COOKIE_NAME=_user                  # Session cookie name
AUTH_COOKIE_PATH=/
AUTH_COOKIE_DOMAIN=
```

## User Type

`User` is a type alias for `auth.User` from the simpauth package. See [simpauth](https://github.com/liut/simpauth) for details.

## Example
---

```go
package main

import (
	"fmt"
	"net/http"

	staffio "github.com/liut/staffio-client"
)

func main() {

	loginPath := "/auth/login"
	staffio.SetLoginPath(loginPath)
	staffio.SetAdminPath("/admin")

	// login start
	http.HandleFunc(loginPath, staffio.LoginHandler)
	// default callback with role admin (role is optional)
	http.Handle("/auth/callback", staffio.AuthCodeCallback("admin"))

	// Or custom hook (ex: with chi)
	router.Route("/auth", func(r chi.Router) {
		r.Get("/login", staffio.LoginHandler)
		r.Get("/logout", staffio.LogoutHandler)
		handleTokenGot := func(ctx context.Context, w http.ResponseWriter, token *staffio.InfoToken) {
			// read token.AccessToken
			// write it into cookie or some db
		}
		handleSignedIn := func(ctx context.Context, w http.ResponseWriter, user *staffio.User) {
			// read user
			// write it into cookie or some db or response to frontend
			// AND SHOULD redirect to the URI of user panel (if not in AJAX)
		}
		cc := &staffio.CodeCallback{
			OnTokenGot: handleTokenGot,
			OnSignedIn: handleSignedIn,
		}
		r.Method(http.MethodGet, "/callback", cc.Handler())
	})

	// use middleware
	authF1 := staffio.Middleware()
	authF1 := staffio.Middleware(staffio.WithRefresh()) // auto refresh token time
	authF1 := staffio.Middleware(staffio.WithRefresh(), staffio.WithURI(loginPath)) // auto refresh and redirect
	http.Handle("/admin", authF1(http.HandlerFunc(handlerAdminWelcome)))
	// more handlers
}

func handlerAdminWelcome(w http.ResponseWriter, r *http.Request) {
	user := staffio.UserFromContext(r.Context())
	fmt.Fprintf(w, "welcome %s", user.Name)
}


// Middleware for gin
func Middleware(opts ...staffio.OptFunc) gin.HandlerFunc {
	option := staffio.NewOption(opts...)
	return func(c *gin.Context) {
		user, err := staffio.UserFromRequest(c.Request)
		if err != nil {
			if option.URI != "" {
				c.Redirect(http.StatusFound, option.URI)
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}
		if option.Refresh && user.NeedRefresh() {
			user.Refresh()
			user.Signin(c.Writer)
		}
		req := c.Request
		c.Request = req.WithContext(staffio.ContextWithUser(req.Context(), user))
		c.Next()
	}
}

// UserFromContext for gin
func UserFromContext(c *gin.Context) (user *User, ok bool) {
	return staffio.UserFromContext(c.Request.Context())
}

// AuthCodeCallback for gin handler which for Check auth with role[s] when auth-code callback
func AuthCodeCallback(roleName ...string) gin.HandlerFunc {
	return gin.WrapH(staffio.AuthCodeCallback(roleName...))
}


// HandlerShowMe for gin
func HandlerShowMe(c *gin.Context) {
	user, ok := staffio.UserFromContext(c.Request.Context())
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"me":    user,
	})
}

```
