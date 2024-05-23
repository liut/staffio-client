package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

var (
	conf2     *oauth2.Config
	cOnce     sync.Once
	prefix    string
	infoURI   string
	envPrefix = "OAUTH"
)

func init() {
	prefix := envOrP("PREFIX", "https://staffio.work")
	infoURI = fixURI(prefix, envOrP("URI_INFO", "info/me"))
}

func confSgt() *oauth2.Config {
	cOnce.Do(func() {
		conf2 = &oauth2.Config{Endpoint: oauth2.Endpoint{
			AuthURL:  fixURI(prefix, envOrP("URI_AUTHORIZE", "authorize")),
			TokenURL: fixURI(prefix, envOrP("URI_TOKEN", "token")),
		}}
		clientID := envOrP("CLIENT_ID", "")
		clientSecret := envOrP("CLIENT_SECRET", "")
		if clientID == "" || clientSecret == "" {
			slog.Warn(envPrefix + "_CLIENT_ID or " + envPrefix + "_CLIENT_SECRET not found in environment")
		} else {
			SetupClient(conf2, clientID, clientSecret)
		}

		SetupRedirectURL(conf2, envOrP("REDIRECT_URL", "/auth/callback"))

		if scopes := strings.Split(envOrP("SCOPES", ""), ","); len(scopes) > 0 {
			SetupScopes(conf2, scopes)
		}
	})
	return conf2
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

// GetOAuth2Config deprecated:
func GetOAuth2Config() *oauth2.Config {
	return confSgt()
}

// Setup oauth2 config
func SetupClient(conf *oauth2.Config, clientID, clientSecret string) {
	if clientID != "" && clientSecret != "" {
		conf.ClientID, conf.ClientSecret = clientID, clientSecret
	}
}
func SetupRedirectURL(conf *oauth2.Config, s string) {
	if len(s) > 0 {
		conf.RedirectURL = s
	}
}
func SetupScopes(conf *oauth2.Config, scopes []string) {
	if len(scopes) > 0 {
		conf.Scopes = scopes
	}
}

// LoginStart generate state into cookie and return redirectURI
func LoginStart(w http.ResponseWriter, r *http.Request) string {
	state := randToken()
	_ = defaultStateStore.Save(w, state)

	if strings.HasPrefix(confSgt().RedirectURL, "/") {
		return confSgt().AuthCodeURL(state, getAuthCodeOption(r))
	}
	return confSgt().AuthCodeURL(state)
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

func envOrP(key, dft string) string {
	if v, ok := os.LookupEnv(envName(key)); ok && len(v) > 0 {
		return v
	}
	if v, ok := os.LookupEnv("STAFFIO_" + key); ok && len(v) > 0 {
		return v
	}
	return envOr(key, dft)
}

func getAuthCodeOption(r *http.Request) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("redirect_uri", getRedirectURI(r))
}

func getRedirectURI(r *http.Request) string {
	if strings.HasPrefix(confSgt().RedirectURL, "/") {
		return getScheme(r) + "://" + r.Host + confSgt().RedirectURL
	}
	return confSgt().RedirectURL
}

func getScheme(r *http.Request) string {
	if r.TLS != nil || r.URL.Scheme == "https" || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
