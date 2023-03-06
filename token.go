package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

func (e InfoError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrCode, e.ErrMessage)
}

// RequestInfoToken ...
func RequestInfoToken(tok *oauth2.Token, roles ...string) (*InfoToken, error) {
	ctxEx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	client := conf.Client(ctxEx, tok)
	uri := infoURI
	if len(roles) > 0 {
		uri = infoURI + "|" + strings.Join(roles, "|")
	}
	info, err := client.Get(uri)
	if err != nil {
		return nil, err
	}
	defer info.Body.Close()

	var it = &InfoToken{}
	err = json.NewDecoder(info.Body).Decode(it)
	if err != nil {
		log.Printf("unmarshal to infoToken err %s, %d, %s", err, info.StatusCode, uri)
		return nil, err
	}
	if it.ErrCode != "" {
		log.Printf("infoToken: %s", it.Error())
		return nil, it
	}
	return it, nil
}
