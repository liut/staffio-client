package client

import (
	"log"
	"net/http"
)

const (
	cKeyState = "staffio_state"
)

type StateStore interface {
	Save(w http.ResponseWriter, state string) error
	Verify(r *http.Request, state string) bool
	Wipe(w http.ResponseWriter, state string)
}

func RegisterStateStore(ss StateStore) {
	defaultStateStore = ss
}

var (
	defaultStateStore StateStore = newStateStore()
)

func newStateStore() StateStore {
	return &stateStoreImpl{}
}

type stateStoreImpl struct{}

func (ssi *stateStoreImpl) Save(w http.ResponseWriter, state string) error {
	StateSet(w, state)
	return nil
}
func (ssi *stateStoreImpl) Verify(r *http.Request, state string) bool {
	return StateGet(r) == state
}
func (ssi *stateStoreImpl) Wipe(w http.ResponseWriter, state string) {
	StateUnset(w)
}

func StateGet(r *http.Request) string {
	if c, err := r.Cookie(cKeyState); err == nil {
		return c.Value
	} else {
		log.Printf("get state fail: %s", err)
	}
	return ""
}

func StateSet(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cKeyState,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
	})
}

func StateUnset(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cKeyState,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	})
}
