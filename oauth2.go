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
)

var (
	conf           *oauth2.Config
	oAuth2Endpoint oauth2.Endpoint
	infoURI        string
	envPrefix      = "OAUTH"
)

func init() {
	prefix := envOr(envName("PREFIX"), "https://staffio.work")
	oAuth2Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/%s", prefix, envOr(envName("EP_AUTHORIZE"), "authorize")),
		TokenURL: fmt.Sprintf("%s/%s", prefix, envOr(envName("EP_TOKEN"), "token")),
	}
	clientID := envOr(envName("CLIENT_ID"), "")
	clientSecret := envOr(envName("CLIENT_SECRET"), "")
	if clientID == "" || clientSecret == "" {
		log.Printf("Warning: %s_CLIENT_ID or %s_CLIENT_SECRET not found in environment", envPrefix, envPrefix)
	}
	infoURI = fmt.Sprintf("%s/%s", prefix, envOr(envName("EP_INFO"), "info"))
	redirectURL := envOr(envName("REDIRECT_URL"), "/auth/callback")
	scopes := strings.Split(envOr(envName("SCOPES"), ""), ",")
	if clientID != "" && clientSecret != "" {
		Setup(redirectURL, clientID, clientSecret, scopes)
	}
}

func envName(k string) string {
	return envPrefix + "_" + k
}

func randToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
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
	state := randToken()
	stateSet(w, state)
	var location string
	if strings.HasPrefix(conf.RedirectURL, "/") {
		location = conf.AuthCodeURL(state, getAuthCodeOption(r))
	} else {
		location = conf.AuthCodeURL(state)
	}

	w.Header().Set("refresh", fmt.Sprintf("1; %s", location))
	title := envOr("AUTH_TITLE", "Staffio")
	_, _ = w.Write([]byte("<html><title>" + title + "</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" +
		location + "'><button style='font-size: 14px;'> Login with " + title + "! </button></a></body></html>"))
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

func getAuthCodeOption(r *http.Request) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("redirect_uri", getRedirectURI(r))
}

func getRedirectURI(r *http.Request) string {
	if strings.HasPrefix(conf.RedirectURL, "/") {
		return getScheme(r) + "://" + r.Host + conf.RedirectURL
	}
	return conf.RedirectURL
}

func getScheme(r *http.Request) string {
	if r.TLS != nil || r.URL.Scheme == "https" || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
