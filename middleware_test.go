package client

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeProvider captures token requests and can fail the next one, without a listener.
type fakeProvider struct {
	mu       sync.Mutex
	forms    []url.Values
	failNext bool
}

func (fp *fakeProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	var body url.Values
	if r.Body != nil {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		body, _ = url.ParseQuery(string(raw))
	}

	fp.mu.Lock()
	fp.forms = append(fp.forms, body)
	fail := fp.failNext
	fp.failNext = false
	fp.mu.Unlock()

	status, payload := http.StatusOK, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`
	if fail {
		status, payload = http.StatusBadRequest, `{"error":"invalid_grant"}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(payload)),
		Request:    r,
	}, nil
}

func (fp *fakeProvider) requests() []url.Values {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return append([]url.Values(nil), fp.forms...)
}

// useFakeProvider routes package HTTP requests through fp for the duration of the test.
func useFakeProvider(t *testing.T, fp *fakeProvider) {
	t.Helper()
	prev := httpClient
	httpClient = &http.Client{Transport: fp}
	t.Cleanup(func() { httpClient = prev })
}

// callback drives one auth-code callback through AuthCodeCallbackWrap with the
// given state cookie, returning the response and whether next was reached.
func callback(state string, cookie *http.Cookie) (*httptest.ResponseRecorder, bool) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet,
		"http://app.example/auth/callback?code=the-code&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	AuthCodeCallbackWrap(next).ServeHTTP(rec, req)
	return rec, reached
}

func TestAuthCodeCallbackWrap_PKCEEndToEnd(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	fp := new(fakeProvider)
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	// login entry produces the authorization URL and the state cookie
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login", nil)
	authURL, err := url.Parse(LoginStart(rec, req))
	require.NoError(t, err)
	challenge := authURL.Query().Get("code_challenge")
	state := authURL.Query().Get("state")
	require.NotEmpty(t, challenge)
	require.NotEmpty(t, state)

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cKeyState {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)

	// provider redirects back with code and state
	cbRec, reached := callback(state, stateCookie)
	require.True(t, reached, "callback should reach next handler: %d %s", cbRec.Code, cbRec.Body.String())

	forms := fp.requests()
	require.Len(t, forms, 1)
	assert.Equal(t, "the-code", forms[0].Get("code"))
	assert.Equal(t, "authorization_code", forms[0].Get("grant_type"))
	verifier := forms[0].Get("code_verifier")
	require.NotEmpty(t, verifier)
	assert.Equal(t, challenge, oauth2.S256ChallengeFromVerifier(verifier))

	// a successful exchange consumes the verifier
	_, reached = callback(state, stateCookie)
	assert.False(t, reached)
	assert.Len(t, fp.requests(), 1, "second callback must not hit the token endpoint")
}

func TestAuthCodeCallbackWrap_InvalidState(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	fp := new(fakeProvider)
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	rec, reached := callback("bogus", &http.Cookie{Name: cKeyState, Value: "other"})

	assert.False(t, reached)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, fp.requests(), "invalid state must not hit the token endpoint")
}

func TestAuthCodeCallbackWrap_MissingVerifier(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	fp := new(fakeProvider)
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	state := randToken()
	rec, reached := callback(state, &http.Cookie{Name: cKeyState, Value: state})

	assert.False(t, reached)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "code_verifier")
	assert.Empty(t, fp.requests())
}

func TestAuthCodeCallbackWrap_ExpiredVerifier(t *testing.T) {
	vs := newVerifierStore(10 * time.Millisecond)
	RegisterVerifierStore(vs)
	fp := new(fakeProvider)
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	state := randToken()
	require.NoError(t, vs.Save(state, "verifier"))
	time.Sleep(40 * time.Millisecond)

	rec, reached := callback(state, &http.Cookie{Name: cKeyState, Value: state})

	assert.False(t, reached)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, fp.requests())
}

func TestAuthCodeCallbackWrap_ExchangeFailureKeepsVerifier(t *testing.T) {
	RegisterVerifierStore(newVerifierStore(time.Minute))
	fp := &fakeProvider{failNext: true}
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	state := randToken()
	require.NoError(t, defaultVerifierStore.Save(state, "the-verifier"))
	cookie := &http.Cookie{Name: cKeyState, Value: state}

	first, reached := callback(state, cookie)
	assert.False(t, reached)
	assert.Equal(t, http.StatusBadRequest, first.Code)

	second, reached := callback(state, cookie)
	assert.True(t, reached, "retry must succeed after a transient token error: %d %s", second.Code, second.Body.String())

	forms := fp.requests()
	require.Len(t, forms, 2)
	assert.Equal(t, "the-verifier", forms[0].Get("code_verifier"))
	assert.Equal(t, "the-verifier", forms[1].Get("code_verifier"))
}

// failingVerifierStore accepts no verifier, standing in for a shared store that
// is unreachable or rejecting writes.
type failingVerifierStore struct{}

func (failingVerifierStore) Save(string, string) error { return errors.New("store unavailable") }
func (failingVerifierStore) Load(string) string        { return "" }
func (failingVerifierStore) Wipe(string)               {}

func TestPKCE_SaveFailureFailsAtCallback(t *testing.T) {
	RegisterVerifierStore(failingVerifierStore{})
	t.Cleanup(func() { RegisterVerifierStore(newVerifierStore(verifierTTL)) })
	fp := new(fakeProvider)
	useFakeProvider(t, fp)
	testProviderConfig(t, "https://staffio.example", "/auth/callback")

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login", nil)
	authURL, err := url.Parse(LoginStart(rec, req))
	require.NoError(t, err)

	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	assert.NotEmpty(t, authURL.Query().Get("code_challenge"), "login must still return an authorization URL")
	assert.Contains(t, logs.String(), state, "save failure must be logged with the state")

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cKeyState {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)

	cbRec, reached := callback(state, stateCookie)
	assert.False(t, reached)
	assert.Equal(t, http.StatusBadRequest, cbRec.Code)
	assert.Contains(t, cbRec.Body.String(), "code_verifier")
	assert.Empty(t, fp.requests())
}
