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

// UserEncoder ...
type UserEncoder = auth.Encoder

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

// Middleware ...
func Middleware(opts ...auth.OptFunc) func(next http.Handler) http.Handler {
	authoriz.With(opts...)
	return authoriz.Middleware()
}

// MiddlewareWordy ...
func MiddlewareWordy(redir bool) func(next http.Handler) http.Handler {
	return authoriz.MiddlewareWordy(redir)
}

// Signin ...
func Signin(user UserEncoder, w http.ResponseWriter) {
	authoriz.Signin(user, w)
}

// Signout ...
func Signout(w http.ResponseWriter) {
	authoriz.Signout(w)
}

// WithURI ...
func WithURI(uri string) auth.OptFunc {
	fn := auth.WithURI(uri)
	authoriz.With(fn)
	return fn
}

// WithRefresh ...
func WithRefresh() auth.OptFunc {
	fn := auth.WithRefresh()
	authoriz.With(fn)
	return fn
}

// WithCookie ...
func WithCookie(strs ...string) auth.OptFunc {
	fn := auth.WithCookie(strs...)
	authoriz.With(fn)
	return fn
}
