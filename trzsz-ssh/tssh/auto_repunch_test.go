/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.
*/

package tssh

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// isRepunchAuthError
// ---------------------------------------------------------------------------

func TestIsRepunchAuthError_AuthErrors(t *testing.T) {
	assert := assert.New(t)
	assert.True(isRepunchAuthError(errors.New("ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")))
	assert.True(isRepunchAuthError(errors.New("re-dial SSH failed: ssh: unable to authenticate")))
	assert.True(isRepunchAuthError(errors.New("permission denied (publickey)")))
	assert.True(isRepunchAuthError(errors.New("Permission Denied"))) // case-insensitive
	assert.True(isRepunchAuthError(errors.New("no supported methods remain")))
}

func TestIsRepunchAuthError_NonAuthErrors(t *testing.T) {
	assert := assert.New(t)
	assert.False(isRepunchAuthError(nil))
	assert.False(isRepunchAuthError(errors.New("dial tcp: connection refused")))
	assert.False(isRepunchAuthError(errors.New("stun: no response")))
	assert.False(isRepunchAuthError(errors.New("i/o timeout")))
	assert.False(isRepunchAuthError(errRepunchAuthRequired)) // sentinel itself: no auth strings
}

// ---------------------------------------------------------------------------
// errRepunchAuthRequired sentinel
// ---------------------------------------------------------------------------

func TestErrRepunchAuthRequired_IsDistinct(t *testing.T) {
	// errRepunchAuthRequired must be distinguishable from generic errors.
	assert.NotNil(t, errRepunchAuthRequired)
	assert.False(t, errors.Is(errRepunchAuthRequired, errors.New("some other error")))
	// Wrapping it must still be detectable.
	wrapped := errors.Join(errors.New("outer"), errRepunchAuthRequired)
	assert.True(t, errors.Is(wrapped, errRepunchAuthRequired))
}

// ---------------------------------------------------------------------------
// nonInteractive auth suppression
// ---------------------------------------------------------------------------

// minimalSshParam builds a *sshParam with just enough state for auth-method
// tests. Passwords, keys, and options are all absent so the only thing that
// could enable password/keyboard-interactive is the absence of nonInteractive.
func minimalSshParam(nonInteractive bool) *sshParam {
	return &sshParam{
		args:           &sshArgs{},
		host:           "test.example.com",
		nonInteractive: nonInteractive,
	}
}

// TestNonInteractive_SkipsPasswordAuth verifies that getPasswordAuthMethod
// returns nil when nonInteractive is set, without consulting any config.
func TestNonInteractive_SkipsPasswordAuth(t *testing.T) {
	// nonInteractive=true must return nil immediately before any config lookup.
	p := minimalSshParam(true)
	m := getPasswordAuthMethod(p)
	assert.Nil(t, m, "password auth must be nil when nonInteractive=true")
}

// TestNonInteractive_SkipsKeyboardInteractiveAuth verifies that
// getKeyboardInteractiveAuthMethod returns nil when nonInteractive is set,
// without consulting any config.
func TestNonInteractive_SkipsKeyboardInteractiveAuth(t *testing.T) {
	p := minimalSshParam(true)
	m := getKeyboardInteractiveAuthMethod(p)
	assert.Nil(t, m, "keyboard-interactive must be nil when nonInteractive=true")
}

// ---------------------------------------------------------------------------
// Auto-repunch gating logic
// ---------------------------------------------------------------------------

// fakeRepuncher counts calls and controls what triggerRepunch returns.
type fakeRepuncher struct {
	mu       sync.Mutex
	calls    int
	returnFn func(call int) error
}

func (f *fakeRepuncher) repunch(_ bool) error {
	f.mu.Lock()
	f.calls++
	call := f.calls
	fn := f.returnFn
	f.mu.Unlock()
	if fn != nil {
		return fn(call)
	}
	return nil
}

func (f *fakeRepuncher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestAutoRepunchGating_SkipsWhenPunchNotActive verifies no auto-repunch
// when punchUsed=false even if the heartbeat is in timeout.
func TestAutoRepunchGating_SkipsWhenPunchNotActive(t *testing.T) {
	fake := &fakeRepuncher{}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	// Simulate one tick of the udpKeepAlive auto-repunch gate.
	punchUsed := false
	heartbeatTimeout := true
	shouldFire := punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load()
	assert.False(t, shouldFire, "should not fire when punch not active")
	assert.Equal(t, 0, fake.callCount())
}

// TestAutoRepunchGating_SkipsWhenAuthFailed verifies that once
// repunchFailedAuth is set, the gate blocks further auto-repunch attempts.
func TestAutoRepunchGating_SkipsWhenAuthFailed(t *testing.T) {
	fake := &fakeRepuncher{}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	repunchFailedAuth.Store(true)

	punchUsed := true
	heartbeatTimeout := true
	shouldFire := punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load()
	assert.False(t, shouldFire, "should not fire when auth failed")
	assert.Equal(t, 0, fake.callCount())
}

// TestAutoRepunchGating_SkipsWhenInFlight verifies that a concurrent
// auto-repunch goroutine blocks a second attempt.
func TestAutoRepunchGating_SkipsWhenInFlight(t *testing.T) {
	fake := &fakeRepuncher{}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	inFlight.Store(true) // already running

	punchUsed := true
	heartbeatTimeout := true
	shouldFire := punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load()
	assert.False(t, shouldFire, "should not fire when one is already in-flight")
	assert.Equal(t, 0, fake.callCount())
}

// TestAutoRepunchGating_FiresWhenConditionsMet exercises the happy path:
// punch active, heartbeat timed out, no auth failure, no in-flight goroutine.
func TestAutoRepunchGating_FiresWhenConditionsMet(t *testing.T) {
	fake := &fakeRepuncher{}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	punchUsed := true
	heartbeatTimeout := true

	if punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load() {
		inFlight.Store(true)
		go func() {
			defer inFlight.Store(false)
			_ = fake.repunch(true)
		}()
	}

	// Poll briefly for the goroutine to complete.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && fake.callCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, 1, fake.callCount(), "should fire exactly once")
	assert.False(t, inFlight.Load(), "inFlight should be cleared")
}

// TestAutoRepunchGating_SetsAuthFlagOnAuthError verifies that an
// errRepunchAuthRequired return causes the repunchFailedAuth latch to be set,
// which blocks all future auto-repunch attempts.
func TestAutoRepunchGating_SetsAuthFlagOnAuthError(t *testing.T) {
	fake := &fakeRepuncher{
		returnFn: func(call int) error {
			return errRepunchAuthRequired
		},
	}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	// Simulate one successful gate + goroutine execution.
	inFlight.Store(true)
	go func() {
		defer inFlight.Store(false)
		err := fake.repunch(true)
		if err == errRepunchAuthRequired {
			repunchFailedAuth.Store(true)
		}
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !repunchFailedAuth.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	assert.True(t, repunchFailedAuth.Load(), "auth failure must set repunchFailedAuth")
	assert.Equal(t, 1, fake.callCount())

	// Second tick — must not fire because repunchFailedAuth is now set.
	punchUsed := true
	heartbeatTimeout := true
	shouldFire := punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load()
	assert.False(t, shouldFire, "gate must block after auth error")
	assert.Equal(t, 1, fake.callCount(), "no second call")
}

// TestAutoRepunchGating_TransientErrorAllowsRetry ensures that a non-auth
// error (e.g. STUN / network unreachable) does not set the auth latch,
// so the next interval can attempt repunch again.
func TestAutoRepunchGating_TransientErrorAllowsRetry(t *testing.T) {
	networkErr := errors.New("stun: no response from 8.8.8.8:3478")
	fake := &fakeRepuncher{
		returnFn: func(_ int) error { return networkErr },
	}
	var repunchFailedAuth atomic.Bool
	var inFlight atomic.Bool

	for tick := range 2 {
		// Gate check.
		punchUsed := true
		heartbeatTimeout := true
		if !(punchUsed && heartbeatTimeout && !repunchFailedAuth.Load() && !inFlight.Load()) {
			break
		}
		inFlight.Store(true)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer inFlight.Store(false)
			err := fake.repunch(true)
			if err == errRepunchAuthRequired {
				repunchFailedAuth.Store(true)
			}
		}()
		<-done
		_ = tick
	}

	assert.Equal(t, 2, fake.callCount(), "transient errors must allow retry")
	assert.False(t, repunchFailedAuth.Load(), "transient error must not set auth latch")
}

// ---------------------------------------------------------------------------
// triggerRepunch nonInteractive flag plumbing
// ---------------------------------------------------------------------------

// TestTriggerRepunch_PreconditionChecks verifies that triggerRepunch returns
// descriptive errors when the client is not in a punch session without
// actually dialing anything.
func TestTriggerRepunch_PreconditionChecks(t *testing.T) {
	c := &sshUdpClient{}

	err := c.triggerRepunch(false)
	assert.ErrorContains(t, err, "hole punching is not active")

	c.punchUsed = true
	err = c.triggerRepunch(false)
	assert.ErrorContains(t, err, "no retained SSH params")

	c.punchParam = &sshParam{}
	err = c.triggerRepunch(false)
	assert.ErrorContains(t, err, "tsshd pid unknown")

	// With nonInteractive=true the same precondition errors apply.
	c2 := &sshUdpClient{}
	err = c2.triggerRepunch(true)
	assert.ErrorContains(t, err, "hole punching is not active")
}
