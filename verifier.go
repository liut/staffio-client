package client

import (
	"sync"
	"time"
)

// verifierTTL 与 provider 的授权码有效期对齐（aurora 的 OAuthAuthorizationExpiration 为 900 秒）。
const verifierTTL = 15 * time.Minute

// verifierMaxItems 是默认内存存储的条目上限。登录入口无需认证，每次请求都会写入一条记录，
// 上限保证持续刷写时内存有界；固定生存期下最早写入的条目最早过期，优先被淘汰。
const verifierMaxItems = 100000

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
	mu       sync.Mutex
	ttl      time.Duration
	maxItems int
	items    map[string]verifierItem
}

func newVerifierStore(ttl time.Duration) VerifierStore {
	return newVerifierStoreWithCap(ttl, verifierMaxItems)
}

func newVerifierStoreWithCap(ttl time.Duration, maxItems int) *verifierStoreImpl {
	return &verifierStoreImpl{ttl: ttl, maxItems: maxItems, items: make(map[string]verifierItem)}
}

func (vsi *verifierStoreImpl) Save(state, verifier string) error {
	now := time.Now()
	vsi.mu.Lock()
	defer vsi.mu.Unlock()
	vsi.sweep(now)
	vsi.evictOldest()
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

// evictOldest 在达到条目上限时淘汰最早过期的条目，需在持有锁时调用。
// 固定生存期下条目按写入顺序过期，因此被淘汰的就是最早那次未完成的登录。
func (vsi *verifierStoreImpl) evictOldest() {
	if vsi.maxItems <= 0 || len(vsi.items) < vsi.maxItems {
		return
	}
	var (
		oldState string
		oldest   time.Time
	)
	for state, it := range vsi.items {
		if oldState == "" || it.expires.Before(oldest) {
			oldState, oldest = state, it.expires
		}
	}
	delete(vsi.items, oldState)
}
