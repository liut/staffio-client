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

// UserInfo for OAuth2
type O2User struct {
	// Subject - Identifier for the User at the `SP`.
	// 主题 - `SP`对用户的标识符。
	Sub string `json:"sub,omitempty"`
	auth.User
}

func (ou O2User) ToUser() User {
	return ou.User
}

type O2Token = oauth2.Token

// InfoToken ...
type InfoToken struct {
	InfoError

	AccessToken  string     `json:"access_token"`
	TokenType    string     `json:"token_type,omitempty"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresIn    int64      `json:"expires_in,omitempty"` // in seconds
	Expiry       time.Time  `json:"expiry,omitempty"`
	User         *O2User    `json:"user,omitempty"`
	Me           *Staff     `json:"me,omitempty"`
	Roles        auth.Names `json:"group,omitempty"`
}

// GetUser 从 InfoToken 中提取用户信息。
// 优先级：Me > User。当两者都为空时返回 false。
// 会通过 ToUser() 提取基础信息，补充 OID（使用 O2User.Sub）、Roles，并调用 Refresh() 更新缓存字段。
func (it *InfoToken) GetUser() (*User, bool) {
	if it.Me == nil && it.User == nil {
		return nil, false
	}

	user := new(User)
	if it.Me != nil {
		*user = it.Me.ToUser()
	} else if it.User != nil {
		*user = it.User.ToUser()
		if len(user.OID) == 0 && len(it.User.Sub) > 0 {
			user.OID = it.User.Sub
		}
	}
	user.Roles = it.Roles
	user.Refresh()

	return user, true
}

func (it *InfoToken) HasRole(slug string) bool {
	return it.Roles.Has(slug)
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

// RequestInfo calls the info API with the given token and unmarshals the response into obj.
// The optional parts are joined with "|" and appended to the info URI.
func RequestInfo(ctx context.Context, tok *oauth2.Token, obj any, parts ...string) error {
	uri := infoURI
	if len(parts) > 0 {
		uri = infoURI + "|" + strings.Join(parts, "|")
	}
	return RequestWith(ctx, uri, tok, obj)
}

// RequestWith performs an HTTP GET request to the specified URI with the OAuth2 token
// and unmarshals the JSON response into obj.
func RequestWith(ctx context.Context, uri string, tok *oauth2.Token, obj any) error {
	ctxEx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	client := confSgt().Client(ctxEx, tok)
	resp, err := client.Get(uri)
	if err != nil {
		slog.Info("get resp fail", "err", err, "uri", "uri")
		return err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(obj)
	if err != nil {
		slog.Info("unmarshal fail", "err", err, "sc", resp.StatusCode, "uri", uri)
		return err
	}
	return nil
}

// RequestInfoToken requests an InfoToken using the given token and optionally filters by roles.
func RequestInfoToken(ctx context.Context, tok *oauth2.Token, roles ...string) (*InfoToken, error) {
	it := new(InfoToken)
	err := RequestInfo(ctx, tok, it, roles...)
	if err != nil {
		return nil, err
	}

	if err = it.GetError(); err != nil {
		slog.Info("infoToken has error ", "err", err)
		return nil, err
	} else {
		slog.Debug("infoToken", "user", it.User)
	}
	it.Expiry = it.GetExpiry()
	return it, nil
}
