package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func GetPrefix() string {
	return prefix
}

func init() {
	prefix = envOrP("PREFIX", "https://staffio.work")
	infoURI = FixURI(prefix, envOrP("URI_INFO", "info/me"))
}

func confSgt() *oauth2.Config {
	cOnce.Do(func() {
		conf2 = &oauth2.Config{Endpoint: oauth2.Endpoint{
			AuthURL:  FixURI(prefix, envOrP("URI_AUTHORIZE", "authorize")),
			TokenURL: FixURI(prefix, envOrP("URI_TOKEN", "token")),
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

func FixURI(pre, s string) string {
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
	verifier := newPKCEVerifier(state)

	cc := confSgt()
	return cc.AuthCodeURL(state, authCodeOptions(cc.RedirectURL, r, verifier)...)
}

// newPKCEVerifier generates a code_verifier and stores it under state for the
// upcoming token exchange. A save failure is logged but does not block the
// redirect; the callback then ends with an explicit verifier-missing error.
func newPKCEVerifier(state string) string {
	verifier := oauth2.GenerateVerifier()
	if err := defaultVerifierStore.Save(state, verifier); err != nil {
		slog.Info("save code_verifier fail", "state", state, "err", err)
	}
	return verifier
}

// authCodeOptions builds the authorization request options: the S256 challenge,
// plus an absolute redirect_uri when the configured one is a relative path.
func authCodeOptions(redirectURL string, r *http.Request, verifier string) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if strings.HasPrefix(redirectURL, "/") {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", resolveRedirectURI(redirectURL, r)))
	}
	return opts
}

type AuthFormData struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// LoginHandler handles login requests. For Ajax requests, returns authorization form data;
// otherwise redirects to the authorization page or displays a login page.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if IsAjax(r) {
		state := randToken()
		_ = defaultStateStore.Save(w, state)
		verifier := newPKCEVerifier(state)
		cc := confSgt()
		data := AuthFormData{
			ResponseType:        "code",
			ClientID:            cc.ClientID,
			RedirectURI:         getRedirectURI(r),
			Scope:               strings.Join(cc.Scopes, " "),
			State:               state,
			CodeChallenge:       oauth2.S256ChallengeFromVerifier(verifier),
			CodeChallengeMethod: "S256",
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data}) //nolint
		return
	}
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
	return resolveRedirectURI(confSgt().RedirectURL, r)
}

func resolveRedirectURI(redirectURL string, r *http.Request) string {
	if strings.HasPrefix(redirectURL, "/") {
		return getScheme(r) + "://" + r.Host + redirectURL
	}
	return redirectURL
}

func getScheme(r *http.Request) string {
	if r.TLS != nil || r.URL.Scheme == "https" || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
