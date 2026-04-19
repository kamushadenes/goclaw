package zalooauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// fakeStore is a minimal in-memory ChannelInstanceStore for token-refresh tests.
// We only exercise Update — other methods are intentionally unimplemented.
// updateN uses atomic.Int32 so concurrent test goroutines can read it
// without the lock.
type fakeStore struct {
	mu        sync.Mutex
	updateN   atomic.Int32
	lastBlob  []byte
	updateErr error
}

func (f *fakeStore) UpdateCount() int { return int(f.updateN.Load()) }

func (f *fakeStore) Update(_ context.Context, _ uuid.UUID, updates map[string]any) error {
	f.updateN.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return f.updateErr
	}
	if v, ok := updates["credentials"]; ok {
		if b, ok := v.([]byte); ok {
			f.lastBlob = b
		}
	}
	return nil
}

// Unused store-interface methods. Kept tight.
func (f *fakeStore) Create(context.Context, *store.ChannelInstanceData) error { return nil }
func (f *fakeStore) Get(context.Context, uuid.UUID) (*store.ChannelInstanceData, error) {
	return nil, errors.New("unused")
}
func (f *fakeStore) GetByName(context.Context, string) (*store.ChannelInstanceData, error) {
	return nil, errors.New("unused")
}
func (f *fakeStore) Delete(context.Context, uuid.UUID) error { return nil }
func (f *fakeStore) ListEnabled(context.Context) ([]store.ChannelInstanceData, error) {
	return nil, nil
}
func (f *fakeStore) ListAll(context.Context) ([]store.ChannelInstanceData, error) { return nil, nil }
func (f *fakeStore) ListAllInstances(context.Context) ([]store.ChannelInstanceData, error) {
	return nil, nil
}
func (f *fakeStore) ListAllEnabled(context.Context) ([]store.ChannelInstanceData, error) {
	return nil, nil
}
func (f *fakeStore) ListPaged(context.Context, store.ChannelInstanceListOpts) ([]store.ChannelInstanceData, error) {
	return nil, nil
}
func (f *fakeStore) CountInstances(context.Context, store.ChannelInstanceListOpts) (int, error) {
	return 0, nil
}

// newRefreshServer counts incoming refresh-token requests and replies with
// fresh tokens. Optional `errBody` overrides the response with a Zalo
// error envelope (HTTP 200 + non-zero error code).
func newRefreshServer(t *testing.T, errBody string) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		if errBody != "" {
			_, _ = w.Write([]byte(errBody))
			return
		}
		// Each call returns a NEW (rotated) refresh token.
		seq := atomic.LoadInt32(&n)
		body := []byte(`{"access_token":"AT-` + itoa(seq) + `","refresh_token":"RT-` + itoa(seq) + `","expires_in":3600}`)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{'0' + byte(n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// newTokenSourceForTest wires a tokenSource against a httptest server.
func newTokenSourceForTest(t *testing.T, srvURL string, expiresAt time.Time, fs *fakeStore) *tokenSource {
	t.Helper()
	creds := &ChannelCreds{
		AppID:        "app",
		SecretKey:    "key",
		AccessToken:  "AT-old",
		RefreshToken: "RT-old",
		ExpiresAt:    expiresAt,
	}
	client := NewClient(5 * time.Second)
	client.oauthBase = srvURL
	return &tokenSource{
		client:     client,
		creds:      creds,
		store:      fs,
		instanceID: uuid.New(),
	}
}

func TestAccess_FreshTokenSkipsRefresh(t *testing.T) {
	t.Parallel()
	srv, count := newRefreshServer(t, "")
	fs := &fakeStore{}

	ts := newTokenSourceForTest(t, srv.URL, time.Now().Add(time.Hour), fs) // 1h until expiry
	got, err := ts.Access(context.Background())
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if got != "AT-old" {
		t.Errorf("Access = %q, want %q", got, "AT-old")
	}
	if n := atomic.LoadInt32(count); n != 0 {
		t.Errorf("refresh hits = %d, want 0 (token still fresh)", n)
	}
	if fs.UpdateCount() != 0 {
		t.Errorf("store.Update calls = %d, want 0", fs.UpdateCount())
	}
}

func TestAccess_StaleTokenTriggersExactlyOneRefresh(t *testing.T) {
	t.Parallel()
	srv, count := newRefreshServer(t, "")
	fs := &fakeStore{}

	// Token expires in 1min — within refreshMargin (5min) → must refresh.
	ts := newTokenSourceForTest(t, srv.URL, time.Now().Add(time.Minute), fs)
	got, err := ts.Access(context.Background())
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if got != "AT-1" {
		t.Errorf("Access = %q, want refreshed AT-1", got)
	}
	if n := atomic.LoadInt32(count); n != 1 {
		t.Errorf("refresh hits = %d, want 1", n)
	}
	if fs.UpdateCount() != 1 {
		t.Errorf("store.Update calls = %d, want 1", fs.UpdateCount())
	}
}

// Single-flight: 10 concurrent Access() calls on a stale token must result
// in exactly ONE upstream refresh call. Mirrors DBTokenSource.Token() single-mutex pattern.
func TestAccess_SingleFlightUnderConcurrency(t *testing.T) {
	t.Parallel()
	srv, count := newRefreshServer(t, "")
	fs := &fakeStore{}
	ts := newTokenSourceForTest(t, srv.URL, time.Now().Add(time.Minute), fs)

	const N = 10
	var wg sync.WaitGroup
	results := make([]string, N)
	errs := make([]error, N)
	start := make(chan struct{})

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx], errs[idx] = ts.Access(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Errorf("goroutine %d: Access err = %v", i, e)
		}
	}
	if n := atomic.LoadInt32(count); n != 1 {
		t.Errorf("refresh hits = %d, want 1 (single-flight broken)", n)
	}
	if fs.UpdateCount() != 1 {
		t.Errorf("store.Update calls = %d, want 1", fs.UpdateCount())
	}
	// All goroutines see the same refreshed token.
	for i, r := range results {
		if r != "AT-1" {
			t.Errorf("goroutine %d got %q, want AT-1", i, r)
		}
	}
}

func TestAccess_AuthExpiredMarksFailedAndReturnsErr(t *testing.T) {
	t.Parallel()
	// Zalo HTTP 200 + non-zero error code with "invalid" message → ErrAuthExpired.
	srv, _ := newRefreshServer(t, `{"error":-118,"message":"invalid_grant: refresh token expired","data":null}`)
	fs := &fakeStore{}
	ts := newTokenSourceForTest(t, srv.URL, time.Now().Add(time.Minute), fs)

	_, err := ts.Access(context.Background())
	if err == nil {
		t.Fatal("expected error on auth-expired refresh")
	}
	if !errors.Is(err, ErrAuthExpired) {
		t.Fatalf("expected ErrAuthExpired, got %T: %v", err, err)
	}
	// On auth-expired, do NOT persist (the old refresh token is dead anyway).
	if fs.UpdateCount() != 0 {
		t.Errorf("store.Update calls = %d on auth-expired refresh, want 0", fs.UpdateCount())
	}
}

func TestClassifyRefreshError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       error
		wantAuth bool
	}{
		{"invalid_grant envelope", &APIError{Code: -118, Message: "invalid_grant"}, true},
		{"expired envelope", &APIError{Code: -123, Message: "refresh token expired"}, true},
		{"transient 5xx", errors.New("http 503"), false},
		{"transient timeout", errors.New("http: read timeout"), false},
		{"nil", nil, false},
		// Below: must NOT escalate. Generic "invalid X" indicates config error
		// or transient validation issue, not refresh-token death.
		{"invalid app_id (config bug)", &APIError{Code: -1, Message: "invalid app_id"}, false},
		{"invalid parameter", &APIError{Code: -2, Message: "invalid parameter"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRefreshError(tc.in)
			if tc.wantAuth && !errors.Is(got, ErrAuthExpired) {
				t.Errorf("input %v → %v, want ErrAuthExpired", tc.in, got)
			}
			if !tc.wantAuth && errors.Is(got, ErrAuthExpired) {
				t.Errorf("input %v → ErrAuthExpired, want transient", tc.in)
			}
		})
	}
}
