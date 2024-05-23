package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/oauth2"

	auth "github.com/liut/simpauth"
)

// InfoToken ...
type InfoToken struct {
	InfoError

	AccessToken  string     `json:"access_token"`
	TokenType    string     `json:"token_type,omitempty"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresIn    int64      `json:"expires_in,omitempty"`
	Expiry       time.Time  `json:"expiry,omitempty"`
	User         *User      `json:"user,omitempty"`
	Me           *Staff     `json:"me,omitempty"`
	Roles        auth.Names `json:"group,omitempty"`
}

// GetExpiry ...
func (tok *InfoToken) GetExpiry() time.Time {
	return time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
}

type InfoError struct {
	ErrCode    string `json:"error,omitempty"`
	ErrMessage string `json:"error_description,omitempty"`
}

func (e InfoError) GetError() error {
	if len(e.ErrCode) > 0 {
		return fmt.Errorf("%s: %s", e.ErrCode, e.ErrMessage)
	}
	return nil
}

func RequestInfo(ctx context.Context, tok *oauth2.Token, obj any, parts ...string) error {
	ctxEx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	client := confSgt().Client(ctxEx, tok)
	uri := infoURI
	if len(parts) > 0 {
		uri = infoURI + "|" + strings.Join(parts, "|")
	}
	info, err := client.Get(uri)
	if err != nil {
		slog.Info("post info fail", "err", err, "uri", "uri")
		return err
	}
	defer info.Body.Close()
	err = json.NewDecoder(info.Body).Decode(obj)
	if err != nil {
		slog.Info("unmarshal to infoToken fail", "err", err, "sc", info.StatusCode, "uri", uri)
		return err
	}
	return nil
}

// RequestInfoToken ...
func RequestInfoToken(tok *oauth2.Token, roles ...string) (*InfoToken, error) {
	it := new(InfoToken)
	err := RequestInfo(context.Background(), tok, it, roles...)
	if err != nil {
		return nil, err
	}

	if err = it.GetError(); err != nil {
		slog.Info("infoToken has error ", "err", err)
		return nil, err
	} else {
		slog.Debug("infoToken", "user", it.User)
	}
	return it, nil
}
