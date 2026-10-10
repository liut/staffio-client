package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifierStore_SaveLoad(t *testing.T) {
	vs := newVerifierStore(time.Minute)

	require.NoError(t, vs.Save("state-1", "verifier-1"))
	assert.Equal(t, "verifier-1", vs.Load("state-1"))
}

func TestVerifierStore_LoadMissing(t *testing.T) {
	vs := newVerifierStore(time.Minute)

	assert.Equal(t, "", vs.Load("never-saved"))
}

func TestVerifierStore_Wipe(t *testing.T) {
	vs := newVerifierStore(time.Minute)
	require.NoError(t, vs.Save("state-1", "verifier-1"))

	vs.Wipe("state-1")
	assert.Equal(t, "", vs.Load("state-1"))
}

func TestVerifierStore_Expiry(t *testing.T) {
	vs := newVerifierStore(10 * time.Millisecond).(*verifierStoreImpl)
	require.NoError(t, vs.Save("state-1", "verifier-1"))

	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, "", vs.Load("state-1"), "expired verifier must not be returned")

	require.NoError(t, vs.Save("state-2", "verifier-2"))
	assert.Len(t, vs.items, 1, "writing must purge the expired entry")
	assert.Equal(t, "verifier-2", vs.Load("state-2"))
}

func TestVerifierStore_Concurrent(t *testing.T) {
	vs := newVerifierStore(time.Minute)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state := fmt.Sprintf("state-%d", i)
			_ = vs.Save(state, "verifier")
			_ = vs.Load(state)
			vs.Wipe(state)
		}()
	}
	wg.Wait()

	for i := range 50 {
		assert.Equal(t, "", vs.Load(fmt.Sprintf("state-%d", i)))
	}
}
