package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

const (
	cKeyState = "staffio_state"
	cKeyToken = "staffio_token"
	cKeyUser  = "staffio_user"
)

var (
	conf           *oauth2.Config
	oAuth2Endpoint oauth2.Endpoint
	infoURI        string
)

func init() {
	prefix := envOr("STAFFIO_PREFIX", "https://staffio.work")
	oAuth2Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/%s", prefix, "authorize"),
		TokenURL: fmt.Sprintf("%s/%s", prefix, "token"),
	}
	clientID := envOr("STAFFIO_CLIENT_ID", "")
	clientSecret := envOr("STAFFIO_CLIENT_SECRET", "")
	if clientID == "" || clientSecret == "" {
		log.Print("Warning: STAFFIO_CLIENT_ID or STAFFIO_CLIENT_SECRET not found in environment")
	}
	infoURI = fmt.Sprintf("%s/%s", prefix, "info/me")
	redirectURL := envOr("STAFFIO_REDIRECT_URL", "/auth/callback")
	scopes := strings.Split(envOr("STAFFIO_SCOPES", ""), ",")
	if clientID != "" && clientSecret != "" {
		Setup(redirectURL, clientID, clientSecret, scopes)
	}
}

func randToken() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// GetOAuth2Config deprecated
func GetOAuth2Config() *oauth2.Config {
	return conf
}

// Setup oauth2 config
func Setup(redirectURL, clientID, clientSecret string, scopes []string) {
	conf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     oAuth2Endpoint,
	}
}

// LoginHandler ...
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	fakeUser := &User{Name: randToken()}
	fakeUser.Refresh()
	state, _ := fakeUser.Encode()
	stateSet(w, state)
	var location string
	if strings.HasPrefix(conf.RedirectURL, "/") {
		location = conf.AuthCodeURL(state, oauth2.SetAuthURLParam("redirect_uri", getScheme(r)+"://"+r.Host+conf.RedirectURL))
	} else {
		location = conf.AuthCodeURL(state)
	}

	w.Header().Set("refresh", fmt.Sprintf("1; %s", location))
	w.Write([]byte("<html><title>Staffio</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" +
		location + "'><button style='font-size: 14px;'> Login with Staffio! </button></a></body></html>"))
}

// LogoutHandler ...
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	Signout(w)
}

func stateGet(r *http.Request) string {
	if c, err := r.Cookie(cKeyState); err == nil {
		return c.Value
	}
	return ""
}

func stateSet(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cKeyState,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
	})
}

func stateUnset(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cKeyState,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})
}

func envOr(key, dft string) string {
	v := os.Getenv(key)
	if v == "" {
		return dft
	}
	return v
}

func getScheme(r *http.Request) string {
	if r.TLS != nil || r.URL.Scheme == "https" || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
