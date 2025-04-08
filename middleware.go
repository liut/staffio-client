package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var (
	tlscfg = &tls.Config{
		InsecureSkipVerify: true,
	}
	httpClient = &http.Client{
		Timeout:   9 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlscfg},
	}

	ErrNoToken = errors.New("oauth2 token not found")
	ErrNoRole  = errors.New("the user not in special roles")

	AdminPath = "/admin/"
	LoginPath = "/auth/login"
)

type ctxKey int

const (
	TokenKey ctxKey = iota
)

func SetLoginPath(path string) {
	LoginPath = path
	WithURI(path)
}

func SetAdminPath(path string) {
	AdminPath = path
}

// AuthMiddleware ...
func AuthMiddleware(redirect bool) func(next http.Handler) http.Handler {
	if redirect {
		WithURI(LoginPath)
		return authoriz.MiddlewareWordy(true)
	}
	return authoriz.Middleware()
}

// AuthCodeCallback Handler for Check auth with role[s] when auth-code callback
func AuthCodeCallback(roles ...string) http.Handler {
	cc := &CodeCallback{InRoles: roles}
	return cc.Handler()
}

// TokenFunc for custom read token
type TokenFunc = func(ctx context.Context, w http.ResponseWriter, it *InfoToken)

// UserFunc for custom read user
type UserFunc = func(ctx context.Context, w http.ResponseWriter, user *User)

// CodeCallback ..
type CodeCallback struct {
	InRoles []string
	// When got a infoToken from the provider
	OnTokenGot TokenFunc
	// When Signed in
	OnSignedIn UserFunc
}

// Handler ...
func (cc *CodeCallback) Handler() http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		it, err := AuthRequestWithRole(r, cc.InRoles...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			slog.Info("auth fail", "roles", cc.InRoles, "err", err)
			return
		}

		if tf := cc.OnTokenGot; tf != nil {
			tf(r.Context(), w, it)
		}

		ue := getToken(it)
		_ = authoriz.Signin(ue, w)

		defaultStateStore.Wipe(w, r.FormValue("state"))

		if cc.OnSignedIn != nil {
			cc.OnSignedIn(r.Context(), w, ue)
			return
		}
		// redirect
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Refresh", fmt.Sprintf("2; %s", AdminPath))
		w.WriteHeader(http.StatusAccepted)
		out := fmt.Sprintf(
			"Welcome back <b>%s</b>. Please waiting, or click <a href=%q>here</a> to go back",
			ue.GetName(), AdminPath)
		_, _ = w.Write([]byte(out))
	}
	return AuthCodeCallbackWrap(http.HandlerFunc(hf))
}

// AuthCodeCallbackWrap is a middleware that injects a InfoToken with roles into the context of callback request
func AuthCodeCallbackWrap(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// verify state value.
		state := r.FormValue("state")
		if !defaultStateStore.Verify(r, state) {
			slog.Info("invalid", "stateF", state, "stateS", StateGet(r), "uri", r.RequestURI)
			http.Error(w, "invalid state: "+state, 400)
			return
		}
		ctx := r.Context()
		ctxEx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

		tok, err := confSgt().Exchange(ctxEx, r.FormValue("code"), getAuthCodeOption(r))
		if err != nil {
			slog.Info("oauth2 exchange fail", "err", err, "euri", confSgt().Endpoint.TokenURL)
			http.Error(w, "oauth2 exchange fail: "+err.Error(), 400)
			return
		}

		ctx = context.WithValue(ctx, TokenKey, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

// UidFromToken extract uid from oauth2.Token
func UidFromToken(tok *oauth2.Token) string {
	if uid, ok := tok.Extra("uid").(string); ok {
		return uid
	}
	return ""
}

// TokenFromContext returns a oauth2.Token from the given context if one is present.
// Returns nil if a oauth2.Token cannot be found.
func TokenFromContext(ctx context.Context) *oauth2.Token {
	if ctx == nil {
		return nil
	}
	if tok, ok := ctx.Value(TokenKey).(*oauth2.Token); ok {
		return tok
	}
	return nil
}

// AuthRequestWithRole called in AuthCallback
func AuthRequestWithRole(r *http.Request, role ...string) (it *InfoToken, err error) {
	ctx := r.Context()
	tok := TokenFromContext(ctx)
	if tok == nil {
		err = ErrNoToken
		return
	}
	it, err = RequestInfoToken(ctx, tok, role...)
	if err != nil {
		return
	}
	for _, rn := range role {
		if !it.Roles.Has(rn) {
			err = ErrNoRole
			break
		}
	}

	return
}

func getToken(it *InfoToken) *User {
	user := new(User)
	if it.Me != nil {
		user.OID = it.Me.OID
		user.UID = it.Me.UID
		user.Name = it.Me.Nickname
		user.Avatar = it.Me.AvatarPath
	} else if it.User != nil {
		user = it.User
	}
	user.Roles = it.Roles

	user.Refresh()
	return user
}
