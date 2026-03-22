package client

import (
	"net/http"

	auth "github.com/liut/simpauth"
)

// User ...
type User = auth.User

// OptFunc ...
type OptFunc = auth.OptFunc

// Authorizer ...
type Authorizer = auth.Authorizer

type IClient interface {
	auth.Authorizer

	LoginStart(w http.ResponseWriter, r *http.Request) string
}

// UserEncoder ...
type UserEncoder interface {
	auth.Encoder
	GetUID() string
	GetName() string
}

// vars
var (
	UserFromRequest = auth.UserFromRequest
	UserFromContext = auth.UserFromContext
	ContextWithUser = auth.ContextWithUser

	NewAuth = auth.New

	authoriz auth.Authorizer
)

func init() {
	authoriz = auth.Default()
	authoriz.With(auth.WithCookie(envOr("AUTH_COOKIE_NAME", "staff"),
		envOr("AUTH_COOKIE_PATH", "/"), envOr("AUTH_COOKIE_DOMAIN", "")))
}

// Middleware returns an HTTP middleware with additional options.
func Middleware(opts ...auth.OptFunc) func(next http.Handler) http.Handler {
	authoriz.With(opts...)
	return authoriz.Middleware()
}

// MiddlewareWordy returns an HTTP middleware with optional redirect behavior.
func MiddlewareWordy(redir bool) func(next http.Handler) http.Handler {
	return authoriz.MiddlewareWordy(redir)
}

// Signin signs in the user by encoding user info into a cookie.
func Signin(user UserEncoder, w http.ResponseWriter) {
	_ = authoriz.Signin(user, w)
}

// Signout signs out the user by clearing the user cookie.
func Signout(w http.ResponseWriter) {
	authoriz.Signout(w)
}

// WithURI sets the URI to redirect to after successful authentication.
func WithURI(uri string) auth.OptFunc {
	fn := auth.WithURI(uri)
	authoriz.With(fn)
	return fn
}

// WithRefresh enables token refresh for the authorizer.
func WithRefresh() auth.OptFunc {
	fn := auth.WithRefresh()
	authoriz.With(fn)
	return fn
}

// WithCookie configures cookie-based session with the given name and optional attributes.
func WithCookie(name string, strs ...string) auth.OptFunc {
	fn := auth.WithCookie(name, strs...)
	authoriz.With(fn)
	return fn
}

// WithHeader configures header-based authentication with the given key (default: token).
func WithHeader(key string) auth.OptFunc {
	fn := auth.WithHeader(key)
	authoriz.With(fn)
	return fn
}
