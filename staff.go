package client

import auth "github.com/liut/simpauth"

// Staff is a retrieved employee struct.
type Staff struct {
	OID            string `json:"oid,omitempty" form:"oid"`           // pk id, ojecct id
	UID            string `json:"uid" form:"uid"`                     // 登录名
	CommonName     string `json:"cn,omitempty" form:"cn"`             // 全名
	GivenName      string `json:"gn,omitempty" form:"gn"`             // 名
	Surname        string `json:"sn,omitempty" form:"sn"`             // 姓
	Nickname       string `json:"nickname,omitempty" form:"nickname"` // 昵称
	Birthday       string `json:"birthday,omitempty" form:"birthday"` // 生日
	Gender         string `json:"gender,omitempty"`                   // 1=male, 2=female, 0=unknown
	Mobile         string `json:"mobile,omitempty"`                   // cell phone number
	Email          string `json:"email,omitempty"`
	EmployeeNumber string `json:"eid,omitempty" form:"eid"`
	EmployeeType   string `json:"etype,omitempty" form:"etitle"`
	AvatarPath     string `json:"avatarPath,omitempty" form:"avatar"`
	Provider       string `json:"provider,omitempty"`
}

func (s Staff) GetOID() string { return s.OID }
func (s Staff) GetUID() string { return s.UID }
func (s Staff) GetName() string {
	if s.Nickname != "" {
		return s.Nickname
	}
	if s.CommonName != "" {
		return s.CommonName
	}
	return s.Surname
}
func (s Staff) GetAvatar() string { return s.AvatarPath }

func (s Staff) ToUser() User {
	return auth.ToUser(s)
}

type RoleMe map[string]any

func (r RoleMe) Has(name string) bool {
	if v, exist := r[name]; exist {
		if g, ok := v.(bool); ok {
			return g
		}
	}
	return false
}
