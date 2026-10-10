package client

import (
	"sync"
	"time"
)

// verifierTTL 与 provider 的授权码有效期对齐（aurora 的 OAuthAuthorizationExpiration 为 900 秒）。
const verifierTTL = 15 * time.Minute

// VerifierStore 按 state 保存 PKCE code verifier。
// 默认实现为进程内存，多实例或进程易重启的部署应注册共享实现（如 redis）。
type VerifierStore interface {
	Save(state, verifier string) error
	Load(state string) string
	Wipe(state string)
}

// RegisterVerifierStore 替换默认的 verifier 存储，注册方式与 RegisterStateStore 同形。
func RegisterVerifierStore(vs VerifierStore) {
	defaultVerifierStore = vs
}

var (
	defaultVerifierStore VerifierStore = newVerifierStore(verifierTTL)
)

type verifierItem struct {
	verifier string
	expires  time.Time
}

type verifierStoreImpl struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]verifierItem
}

func newVerifierStore(ttl time.Duration) VerifierStore {
	return &verifierStoreImpl{ttl: ttl, items: make(map[string]verifierItem)}
}

func (vsi *verifierStoreImpl) Save(state, verifier string) error {
	now := time.Now()
	vsi.mu.Lock()
	defer vsi.mu.Unlock()
	vsi.sweep(now)
	vsi.items[state] = verifierItem{verifier: verifier, expires: now.Add(vsi.ttl)}
	return nil
}

func (vsi *verifierStoreImpl) Load(state string) string {
	vsi.mu.Lock()
	defer vsi.mu.Unlock()
	it, ok := vsi.items[state]
	if !ok {
		return ""
	}
	if time.Now().After(it.expires) {
		delete(vsi.items, state)
		return ""
	}
	return it.verifier
}

func (vsi *verifierStoreImpl) Wipe(state string) {
	vsi.mu.Lock()
	defer vsi.mu.Unlock()
	delete(vsi.items, state)
}

// sweep 惰性清理已过期条目，需在持有锁时调用。
func (vsi *verifierStoreImpl) sweep(now time.Time) {
	for state, it := range vsi.items {
		if now.After(it.expires) {
			delete(vsi.items, state)
		}
	}
}
