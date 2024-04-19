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

var (
	conf      *oauth2.Config
	infoURI   string
	envPrefix = "OAUTH"
)

func init() {
	prefix := envOr(envName("PREFIX"), "https://staffio.work")

	conf = &oauth2.Config{Endpoint: oauth2.Endpoint{
		AuthURL:  fixURI(prefix, envOr(envName("URI_AUTHORIZE"), "authorize")),
		TokenURL: fixURI(prefix, envOr(envName("URI_TOKEN"), "token")),
	}}
	clientID := envOr(envName("CLIENT_ID"), "")
	clientSecret := envOr(envName("CLIENT_SECRET"), "")
	if clientID == "" || clientSecret == "" {
		log.Printf("Warning: %s_CLIENT_ID or %s_CLIENT_SECRET not found in environment", envPrefix, envPrefix)
	} else {
		SetupClient(clientID, clientSecret)
	}

	SetupRedirectURL(envOr(envName("REDIRECT_URL"), "/auth/callback"))

	if scopes := strings.Split(envOr(envName("SCOPES"), ""), ","); len(scopes) > 0 {
		SetupScopes(scopes)
	}

	infoURI = fixURI(prefix, envOr(envName("URI_INFO"), "info/me"))
}

func envName(k string) string {
	return envPrefix + "_" + k
}

func fixURI(pre, s string) string {
	if strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "http:") {
		return s
	}
	if strings.HasPrefix(s, "/") {
		return pre + s
	}
	return pre + "/" + s
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
func SetupClient(clientID, clientSecret string) {
	if clientID != "" && clientSecret != "" {
		conf.ClientID, conf.ClientSecret = clientID, clientSecret
	}
}
func SetupRedirectURL(s string) {
	if len(s) > 0 {
		conf.RedirectURL = s
	}
}
func SetupScopes(scopes []string) {
	if len(scopes) > 0 {
		conf.Scopes = scopes
	}
}

// LoginStart generate state into cookie and return redirectURI
func LoginStart(w http.ResponseWriter, r *http.Request) string {
	state := randToken()
	_ = defaultStateStore.Save(w, state)

	if strings.HasPrefix(conf.RedirectURL, "/") {
		return conf.AuthCodeURL(state, getAuthCodeOption(r))
	}
	return conf.AuthCodeURL(state)
}

// LoginHandler ...
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	location := LoginStart(w, r)
	w.Header().Set("refresh", fmt.Sprintf("1; %s", location))
	title := envOr("AUTH_TITLE", "Staffio")
	_, _ = w.Write([]byte("<html><title>" + title + "</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" +
		location + "'><button style='font-size: 14px;'> Login with " + title + "! </button></a></body></html>"))
}

// LogoutHandler ...
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	Signout(w)
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
