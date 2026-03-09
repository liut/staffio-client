package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInfoError_GetError(t *testing.T) {
	tests := []struct {
		name      string
		err       InfoError
		expectNil bool
	}{
		{
			name:      "有错误",
			err:       InfoError{ErrCode: "invalid_request", ErrMessage: "missing parameter"},
			expectNil: false,
		},
		{
			name:      "无错误",
			err:       InfoError{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.err.GetError()
			if tt.expectNil {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestInfoToken_HasRole(t *testing.T) {
	it := &InfoToken{
		Roles: []string{"admin", "user"},
	}

	tests := []struct {
		name     string
		slug     string
		expected bool
	}{
		{"存在的角色", "admin", true},
		{"不存在的角色", "guest", false},
		{"空角色", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := it.HasRole(tt.slug)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInfoToken_GetExpiry(t *testing.T) {
	it := &InfoToken{
		ExpiresIn: 3600,
	}

	expiry := it.GetExpiry()
	expected := expiry.Add(-3600 * time.Second)

	assert.True(t, expiry.After(expected), "Expiry should be in the future")
}
