package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"golang.org/x/oauth2"

	auth "github.com/liut/simpauth"
)

// InfoToken ...
type InfoToken struct {
	AccessToken  string     `json:"access_token"`
	TokenType    string     `json:"token_type,omitempty"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresIn    int64      `json:"expires_in,omitempty"`
	Expiry       time.Time  `json:"expiry,omitempty"`
	Me           Staff      `json:"me,omitempty"`
	Roles        auth.Names `json:"group,omitempty"`
}

// GetExpiry ...
func (tok *InfoToken) GetExpiry() time.Time {
	return time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
}

type infoError struct {
	Code    string `json:"error,omitempty"`
	Message string `json:"error_description,omitempty"`
}

func (e *infoError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
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
	data, err := ioutil.ReadAll(info.Body)
	if err != nil {
		log.Printf("read infoURI err %s", err)
		return nil, err
	}

	infoErr := &infoError{}
	if e := json.Unmarshal(data, infoErr); e != nil {
		return nil, e
	}

	if infoErr.Code != "" {
		return nil, infoErr
	}

	var token = &InfoToken{}
	err = json.Unmarshal(data, token)
	if err != nil {
		log.Printf("unmarshal to infoToken err %s, data %s", err, data)
		return nil, err
	}
	return token, nil
}
