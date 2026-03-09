package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaff_GetName(t *testing.T) {
	tests := []struct {
		name     string
		staff    Staff
		expected string
	}{
		{
			name:     "nickname优先",
			staff:    Staff{Nickname: "小王", CommonName: "王小明", Surname: "王"},
			expected: "小王",
		},
		{
			name:     "无nickname用commonName",
			staff:    Staff{CommonName: "王小明", Surname: "王"},
			expected: "王小明",
		},
		{
			name:     "无nickname和commonName用surname",
			staff:    Staff{Surname: "王"},
			expected: "王",
		},
		{
			name:     "全部为空",
			staff:    Staff{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.staff.GetName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRoleMe_Has(t *testing.T) {
	tests := []struct {
		name     string
		roleMe   RoleMe
		key      string
		expected bool
	}{
		{
			name:     "存在且为true",
			roleMe:   RoleMe{"admin": true},
			key:      "admin",
			expected: true,
		},
		{
			name:     "存在且为false",
			roleMe:   RoleMe{"admin": false},
			key:      "admin",
			expected: false,
		},
		{
			name:     "不存在",
			roleMe:   RoleMe{"admin": true},
			key:      "user",
			expected: false,
		},
		{
			name:     "值为非bool",
			roleMe:   RoleMe{"admin": "yes"},
			key:      "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.roleMe.Has(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}
