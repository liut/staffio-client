package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// testProviderConfig points the package OAuth2 config at endpoint and rebuilds it
// from the current environment, so tests are independent of the confSgt() singleton.
func testProviderConfig(t *testing.T, endpoint, redirectURL string) *oauth2.Config {
	t.Helper()
	t.Setenv("OAUTH_CLIENT_ID", "test-client")
	t.Setenv("OAUTH_CLIENT_SECRET", "test-secret")
	t.Setenv("OAUTH_SCOPES", "openid")
	prevPrefix := prefix
	t.Cleanup(func() { prefix = prevPrefix })
	prefix = endpoint

	t.Setenv("OAUTH_REDIRECT_URL", redirectURL)
	conf2 = nil
	cOnce = sync.Once{}

	cc := confSgt()
	cc.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	return cc
}

func loginAttempt(t *testing.T) (state, verifier string, query url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login", nil)
	raw := LoginStart(rec, req)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	query = u.Query()
	state = query.Get("state")
	require.NotEmpty(t, state)
	verifier = defaultVerifierStore.Load(state)
	require.NotEmpty(t, verifier)
	return state, verifier, query
}

func TestLoginStart_IncludesPKCE(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	state, verifier, query := loginAttempt(t)

	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(verifier), query.Get("code_challenge"))
	assert.NotEqual(t, verifier, query.Get("code_challenge"))
	assert.Equal(t, verifier, defaultVerifierStore.Load(state), "state in the URL must key the stored verifier")

	// a relative redirect_uri is still resolved against the request host
	assert.Equal(t, "http://app.example/auth/callback", query.Get("redirect_uri"))
}

func TestLoginStart_DistinctAttempts(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	state1, verifier1, _ := loginAttempt(t)
	state2, verifier2, _ := loginAttempt(t)

	assert.NotEqual(t, state1, state2)
	assert.NotEqual(t, verifier1, verifier2)
	assert.Equal(t, verifier1, defaultVerifierStore.Load(state1))
	assert.Equal(t, verifier2, defaultVerifierStore.Load(state2))
}

func TestLoginStart_AbsoluteRedirect(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	testProviderConfig(t, "https://staffio.example", "https://app.example/auth/callback")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login", nil)
	u, err := url.Parse(LoginStart(rec, req))
	require.NoError(t, err)

	assert.Equal(t, "https://app.example/auth/callback", u.Query().Get("redirect_uri"))
	assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
}

func TestLoginHandler_AjaxForm(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login", nil)
	req.Header.Set("Accept", "application/json")
	LoginHandler(rec, req)

	// assert the wire contract by raw key, not by re-decoding into AuthFormData
	for _, key := range []string{"code_challenge", "code_challenge_method"} {
		assert.Contains(t, rec.Body.String(), `"`+key+`"`)
	}

	var out struct {
		Data AuthFormData `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))

	d := out.Data
	assert.Equal(t, "code", d.ResponseType)
	assert.Equal(t, "test-client", d.ClientID)
	assert.Equal(t, "http://app.example/auth/callback", d.RedirectURI)
	assert.Equal(t, "openid", d.Scope)
	require.NotEmpty(t, d.State)
	assert.Equal(t, "S256", d.CodeChallengeMethod)

	verifier := defaultVerifierStore.Load(d.State)
	require.NotEmpty(t, verifier)
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(verifier), d.CodeChallenge)
}
