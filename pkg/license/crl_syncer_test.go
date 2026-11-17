package license

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCRLSyncer_HTTP200_SuccessAndCache(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	claims := RevocationListClaims{
		ID:         "crl-test-200",
		Issuer:     "divmora.com/crl",
		Product:    "gitlab-fleet-governor",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
		Entries: []RevocationEntry{
			{ID: "revoked-lic-001", RevokedAt: now, Reason: "compromised"},
		},
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	etag := `"crl-hash-12345"`
	lastMod := now.Format(http.TimeFormat)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastMod)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedToken))
	}))
	defer ts.Close()

	cacheDir := t.TempDir()
	cacheFile := filepath.Join(cacheDir, "crl.cache")

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:             ts.URL,
		KeyRing:         ring,
		CacheFile:       cacheFile,
		ExpectedProduct: "gitlab-fleet-governor",
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	res, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if res.Source != SyncSourceRemote {
		t.Errorf("expected Source %v, got %v", SyncSourceRemote, res.Source)
	}
	if res.ETag != etag {
		t.Errorf("expected ETag %s, got %s", etag, res.ETag)
	}
	if res.Claims == nil || res.Claims.ID != "crl-test-200" {
		t.Errorf("unexpected claims: %+v", res.Claims)
	}

	// Verify local cache file was written
	cacheBytes, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}
	if string(cacheBytes) != signedToken {
		t.Errorf("cache file content mismatch")
	}

	// Verify thread-safe getters
	if syncer.Claims() == nil || syncer.Claims().ID != "crl-test-200" {
		t.Errorf("syncer.Claims() returned unexpected claims")
	}
	if syncer.Raw() != signedToken {
		t.Errorf("syncer.Raw() returned unexpected token")
	}
}

func TestCRLSyncer_HTTP304_NotModified(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	claims := RevocationListClaims{
		ID:         "crl-test-304",
		Issuer:     "divmora.com/crl",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
		Entries: []RevocationEntry{
			{ID: "lic-304", RevokedAt: now},
		},
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	etag := `"etag-304"`
	var requestCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(signedToken))
			return
		}

		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedToken))
	}))
	defer ts.Close()

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:     ts.URL,
		KeyRing: ring,
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	// First sync -> 200 OK
	res1, err := syncer.Sync(context.Background())
	if err != nil || res1.Source != SyncSourceRemote {
		t.Fatalf("initial sync failed: %v", err)
	}

	// Second sync -> 304 Not Modified
	res2, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if res2.Source != SyncSourceNotModified {
		t.Errorf("expected Source %v, got %v", SyncSourceNotModified, res2.Source)
	}
	if res2.Claims == nil || res2.Claims.ID != "crl-test-304" {
		t.Errorf("expected preserved claims, got %+v", res2.Claims)
	}
}

func TestCRLSyncer_TamperedSignatureRejected(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	claims := RevocationListClaims{
		ID:         "crl-tampered",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
	}

	token, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	// Tamper with payload
	parts := strings.Split(token, ".")
	tamperedToken := fmt.Sprintf("%s.%s.%s", parts[0], parts[1]+"tampered", parts[2])

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(tamperedToken))
	}))
	defer ts.Close()

	cacheFile := filepath.Join(t.TempDir(), "crl.cache")

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:       ts.URL,
		KeyRing:   ring,
		CacheFile: cacheFile,
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	_, err = syncer.Sync(context.Background())
	if err == nil {
		t.Fatalf("expected error on tampered CRL signature, got nil")
	}
	if !errors.Is(err, ErrInvalidCRL) {
		t.Errorf("expected ErrInvalidCRL, got: %v", err)
	}

	// Cache file should not have been written
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Errorf("cache file should NOT exist after verification failure")
	}
}

func TestCRLSyncer_NetworkFailure_CacheFallback(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	claims := RevocationListClaims{
		ID:         "crl-cached-fallback",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
		Entries: []RevocationEntry{
			{ID: "revoked-cached-1", RevokedAt: now},
		},
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	cacheFile := filepath.Join(t.TempDir(), "crl.cache")
	if err := os.WriteFile(cacheFile, []byte(signedToken), 0644); err != nil {
		t.Fatalf("failed to write initial cache: %v", err)
	}

	// Server that immediately closes or returns 500
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	serverURL := ts.URL
	ts.Close() // Close server so network connection is refused

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:       serverURL,
		KeyRing:   ring,
		CacheFile: cacheFile,
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	res, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected graceful fallback to cache, got error: %v", err)
	}

	if res.Source != SyncSourceCache {
		t.Errorf("expected Source %v, got %v", SyncSourceCache, res.Source)
	}
	if res.NetworkError == nil {
		t.Errorf("expected non-nil NetworkError reporting network failure")
	}
	if res.Claims == nil || res.Claims.ID != "crl-cached-fallback" {
		t.Errorf("unexpected cached claims: %+v", res.Claims)
	}
}

func TestCRLSyncer_StrictExpiry(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	past := time.Now().UTC().Add(-48 * time.Hour)
	claims := RevocationListClaims{
		ID:         "crl-expired",
		IssuedAt:   past.Add(-24 * time.Hour),
		NextUpdate: past, // Expired 48 hours ago
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedToken))
	}))
	defer ts.Close()

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:          ts.URL,
		KeyRing:      ring,
		StrictExpiry: true,
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	_, err = syncer.Sync(context.Background())
	if err == nil {
		t.Fatalf("expected ErrCRLExpired, got nil")
	}
	if !errors.Is(err, ErrCRLExpired) {
		t.Errorf("expected ErrCRLExpired, got: %v", err)
	}
}

func TestCRLSyncer_ProductScopeMismatch(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	claims := RevocationListClaims{
		ID:         "crl-other-product",
		Product:    "other-product",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedToken))
	}))
	defer ts.Close()

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:             ts.URL,
		KeyRing:         ring,
		ExpectedProduct: "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	_, err = syncer.Sync(context.Background())
	if err == nil {
		t.Fatalf("expected ErrProductMismatch, got nil")
	}
	if !errors.Is(err, ErrProductMismatch) {
		t.Errorf("expected ErrProductMismatch, got: %v", err)
	}
}

func TestCRLSyncer_MaxDownloadBytes(t *testing.T) {
	pub, _ := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("A", 200)))
	}))
	defer ts.Close()

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:              ts.URL,
		KeyRing:          ring,
		MaxDownloadBytes: 50, // Small limit
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	_, err = syncer.Sync(context.Background())
	if err == nil {
		t.Fatalf("expected error exceeding max download bytes, got nil")
	}
	if !errors.Is(err, ErrCRLSyncFailed) {
		t.Errorf("expected ErrCRLSyncFailed, got: %v", err)
	}
}

func TestCRLSyncer_UnquotedAndWeakETagHandling(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)

	now := time.Now().UTC()
	claims := RevocationListClaims{
		ID:         "crl-test-etag-robustness",
		Issuer:     "divmora.com/crl",
		IssuedAt:   now,
		NextUpdate: now.Add(24 * time.Hour),
		Entries:    []RevocationEntry{},
	}

	signedToken, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}

	var requestCount int32
	var receivedIfNoneMatch string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		receivedIfNoneMatch = r.Header.Get("If-None-Match")

		if count == 1 {
			// Simulate a server returning an unquoted ETag
			w.Header().Set("ETag", "unquoted-opaque-tag-12345")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(signedToken))
			return
		}

		// On second request, verify client sent properly canonicalized RFC 7232 quoted If-None-Match
		if r.Header.Get("If-None-Match") == `"unquoted-opaque-tag-12345"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedToken))
	}))
	defer ts.Close()

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:     ts.URL,
		KeyRing: ring,
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	// 1st sync: server sent unquoted ETag
	res1, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync 1 failed: %v", err)
	}
	if res1.ETag != `"unquoted-opaque-tag-12345"` {
		t.Errorf("expected canonicalized ETag %q, got %q", `"unquoted-opaque-tag-12345"`, res1.ETag)
	}
	if res1.CleanETag() != "unquoted-opaque-tag-12345" {
		t.Errorf("expected clean ETag %q, got %q", "unquoted-opaque-tag-12345", res1.CleanETag())
	}

	// 2nd sync: should send quoted If-None-Match and receive 304
	res2, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync 2 failed: %v", err)
	}
	if res2.Source != SyncSourceNotModified {
		t.Errorf("expected Source %v, got %v", SyncSourceNotModified, res2.Source)
	}
	if receivedIfNoneMatch != `"unquoted-opaque-tag-12345"` {
		t.Errorf("expected server to receive quoted If-None-Match %q, got %q", `"unquoted-opaque-tag-12345"`, receivedIfNoneMatch)
	}
}

// signVersionedCRL mints a signed CRL with the given sequence, issue time and NextUpdate for rollback/freshness tests.
func signVersionedCRL(t *testing.T, priv ed25519.PrivateKey, id string, seq uint64, issued, next time.Time, revoked ...string) string {
	t.Helper()
	claims := RevocationListClaims{
		ID:         id,
		Issuer:     "divmora.com/crl",
		Product:    "gitlab-fleet-governor",
		Sequence:   seq,
		IssuedAt:   issued,
		NextUpdate: next,
	}
	for _, r := range revoked {
		claims.Entries = append(claims.Entries, RevocationEntry{ID: r, RevokedAt: issued, Reason: "test"})
	}
	tok, err := SignCRL(claims, priv)
	if err != nil {
		t.Fatalf("SignCRL failed: %v", err)
	}
	return tok
}

// switchableCRLServer serves whatever token is currently stored, always with HTTP 200 and no validators,
// emulating a customer-run mirror that can choose what to serve.
func switchableCRLServer(t *testing.T, initial string) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var current atomic.Value
	current.Store(initial)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(current.Load().(string)))
	}))
	t.Cleanup(ts.Close)
	return ts, &current
}

func TestCompareCRLVersion(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	cases := []struct {
		name string
		a, b *RevocationListClaims
		want int
	}{
		{"nil vs nil", nil, nil, 0},
		{"nil older", nil, &RevocationListClaims{IssuedAt: t0}, -1},
		{"higher sequence wins over later issued_at", &RevocationListClaims{Sequence: 3, IssuedAt: t0}, &RevocationListClaims{Sequence: 2, IssuedAt: t1}, 1},
		{"legacy unsequenced is older than sequenced", &RevocationListClaims{IssuedAt: t1}, &RevocationListClaims{Sequence: 1, IssuedAt: t0}, -1},
		{"same sequence falls back to issued_at", &RevocationListClaims{Sequence: 5, IssuedAt: t0}, &RevocationListClaims{Sequence: 5, IssuedAt: t1}, -1},
		{"identical", &RevocationListClaims{Sequence: 5, IssuedAt: t0}, &RevocationListClaims{Sequence: 5, IssuedAt: t0}, 0},
		{"unsequenced by issued_at", &RevocationListClaims{IssuedAt: t1}, &RevocationListClaims{IssuedAt: t0}, 1},
	}
	for _, tc := range cases {
		if got := CompareCRLVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: CompareCRLVersion = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestCRLSyncer_RollbackRejected_CacheKept(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	now := time.Now().UTC()

	newer := signVersionedCRL(t, priv, "crl-seq-2", 2, now, now.Add(24*time.Hour), "lic-revoked-in-seq-2")
	older := signVersionedCRL(t, priv, "crl-seq-1", 1, now.Add(-time.Hour), now.Add(24*time.Hour))

	ts, serving := switchableCRLServer(t, newer)
	cacheFile := filepath.Join(t.TempDir(), "crl.cache")

	syncer, err := NewCRLSyncer(CRLSyncConfig{
		URL:             ts.URL,
		KeyRing:         ring,
		CacheFile:       cacheFile,
		ExpectedProduct: "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}
	if _, err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}

	// Mirror replays an older, validly signed CRL that predates the revocation.
	serving.Store(older)
	_, err = syncer.Sync(context.Background())
	if !errors.Is(err, ErrCRLRollback) {
		t.Fatalf("expected ErrCRLRollback, got: %v", err)
	}

	if got := syncer.Claims(); got == nil || got.ID != "crl-seq-2" {
		t.Fatalf("expected in-memory CRL to remain crl-seq-2, got %+v", got)
	}
	if _, revoked := syncer.Claims().IsRevoked("lic-revoked-in-seq-2"); !revoked {
		t.Fatalf("revocation from newer CRL was lost")
	}
	cached, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("failed to read cache: %v", err)
	}
	if string(cached) != newer {
		t.Fatalf("cache file was overwritten by rolled-back CRL")
	}

	// A fresh process sharing the cache must also reject the replay (cache file is the high-water mark).
	syncer2, err := NewCRLSyncer(CRLSyncConfig{
		URL:             ts.URL,
		KeyRing:         ring,
		CacheFile:       cacheFile,
		ExpectedProduct: "gitlab-fleet-governor",
	})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}
	if _, err := syncer2.Sync(context.Background()); !errors.Is(err, ErrCRLRollback) {
		t.Fatalf("expected ErrCRLRollback against cache file, got: %v", err)
	}
}

func TestCRLSyncer_RollbackRejected_ByIssuedAtWithoutSequence(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	now := time.Now().UTC()

	newer := signVersionedCRL(t, priv, "crl-legacy-new", 0, now, now.Add(24*time.Hour))
	older := signVersionedCRL(t, priv, "crl-legacy-old", 0, now.Add(-48*time.Hour), now.Add(24*time.Hour))

	ts, serving := switchableCRLServer(t, newer)
	syncer, err := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}
	if _, err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}
	serving.Store(older)
	if _, err := syncer.Sync(context.Background()); !errors.Is(err, ErrCRLRollback) {
		t.Fatalf("expected ErrCRLRollback, got: %v", err)
	}
	if syncer.Claims().ID != "crl-legacy-new" {
		t.Fatalf("expected newer CRL to be kept, got %s", syncer.Claims().ID)
	}
}

func TestCRLSyncer_EqualOrNewerAccepted(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	now := time.Now().UTC()

	legacy := signVersionedCRL(t, priv, "crl-legacy", 0, now, now.Add(24*time.Hour))
	seq1 := signVersionedCRL(t, priv, "crl-seq-1", 1, now.Add(-time.Hour), now.Add(24*time.Hour))
	// Higher sequence wins even if its issued_at is earlier (issuer clock skew).
	seq2 := signVersionedCRL(t, priv, "crl-seq-2", 2, now.Add(-2*time.Hour), now.Add(24*time.Hour))

	ts, serving := switchableCRLServer(t, legacy)
	cacheFile := filepath.Join(t.TempDir(), "crl.cache")
	syncer, err := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, CacheFile: cacheFile})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}

	steps := []struct {
		token  string
		wantID string
	}{
		{legacy, "crl-legacy"},
		{legacy, "crl-legacy"}, // identical CRL re-served: accepted
		{seq1, "crl-seq-1"},    // first sequenced CRL supersedes legacy
		{seq1, "crl-seq-1"},    // equal sequence: accepted
		{seq2, "crl-seq-2"},    // newer: accepted
	}
	for i, st := range steps {
		serving.Store(st.token)
		res, err := syncer.Sync(context.Background())
		if err != nil {
			t.Fatalf("step %d: unexpected error: %v", i, err)
		}
		if res.Source != SyncSourceRemote || res.Claims.ID != st.wantID {
			t.Fatalf("step %d: expected remote %s, got %s %s", i, st.wantID, res.Source, res.Claims.ID)
		}
	}
	cached, _ := os.ReadFile(cacheFile)
	if string(cached) != seq2 {
		t.Fatalf("expected cache to hold newest CRL")
	}

	// Going back to the legacy unsequenced CRL is now a rollback.
	serving.Store(legacy)
	if _, err := syncer.Sync(context.Background()); !errors.Is(err, ErrCRLRollback) {
		t.Fatalf("expected ErrCRLRollback for legacy CRL after sequenced CRL, got: %v", err)
	}
}

func TestCRLSyncer_CacheFileOlderThanMemory(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	now := time.Now().UTC()

	newer := signVersionedCRL(t, priv, "crl-seq-9", 9, now, now.Add(24*time.Hour), "lic-revoked-late")
	older := signVersionedCRL(t, priv, "crl-seq-4", 4, now.Add(-time.Hour), now.Add(24*time.Hour))

	ts, _ := switchableCRLServer(t, newer)
	cacheFile := filepath.Join(t.TempDir(), "crl.cache")
	syncer, err := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, CacheFile: cacheFile})
	if err != nil {
		t.Fatalf("NewCRLSyncer failed: %v", err)
	}
	if _, err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}

	// Cache file gets replaced with an older CRL (e.g. restored backup), then the network goes away.
	if err := os.WriteFile(cacheFile, []byte(older), 0644); err != nil {
		t.Fatalf("failed to overwrite cache: %v", err)
	}
	ts.Close()

	res, err := syncer.Sync(context.Background())
	if err != nil {
		t.Fatalf("expected cache fallback, got error: %v", err)
	}
	if res.Source != SyncSourceCache {
		t.Fatalf("expected cache source, got %s", res.Source)
	}
	if res.Claims.ID != "crl-seq-9" || syncer.Claims().ID != "crl-seq-9" {
		t.Fatalf("expected newer in-memory CRL to win over older cache file, got %s", res.Claims.ID)
	}
	if _, revoked := res.Claims.IsRevoked("lic-revoked-late"); !revoked {
		t.Fatalf("revocation lost after falling back to older cache file")
	}
}

func TestCRLSyncer_Freshness_DefaultMaxStaleness(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	lateButTolerated := signVersionedCRL(t, priv, "crl-late", 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour))
	tooStale := signVersionedCRL(t, priv, "crl-stale", 2, now.Add(-30*24*time.Hour), now.Add(-8*24*time.Hour))
	perpetual := signVersionedCRL(t, priv, "crl-perpetual", 3, now.Add(-365*24*time.Hour), time.Time{})

	t.Run("within grace accepted", func(t *testing.T) {
		ts, _ := switchableCRLServer(t, lateButTolerated)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, Now: clock})
		if _, err := s.Sync(context.Background()); err != nil {
			t.Fatalf("expected CRL 2 days past next_update to be accepted, got: %v", err)
		}
	})

	t.Run("beyond default max staleness rejected and cache kept", func(t *testing.T) {
		cacheFile := filepath.Join(t.TempDir(), "crl.cache")
		ts, serving := switchableCRLServer(t, lateButTolerated)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, CacheFile: cacheFile, Now: clock})
		if _, err := s.Sync(context.Background()); err != nil {
			t.Fatalf("initial sync failed: %v", err)
		}
		serving.Store(tooStale)
		_, err := s.Sync(context.Background())
		if !errors.Is(err, ErrCRLExpired) {
			t.Fatalf("expected ErrCRLExpired for CRL 8 days past next_update, got: %v", err)
		}
		if s.Claims().ID != "crl-late" {
			t.Fatalf("expected previous CRL to be kept, got %s", s.Claims().ID)
		}
		if cached, _ := os.ReadFile(cacheFile); string(cached) != lateButTolerated {
			t.Fatalf("stale download must not overwrite cache")
		}
	})

	t.Run("negative max staleness restores legacy behaviour", func(t *testing.T) {
		ts, _ := switchableCRLServer(t, tooStale)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, MaxStaleness: -1, Now: clock})
		if _, err := s.Sync(context.Background()); err != nil {
			t.Fatalf("expected stale CRL to be accepted with MaxStaleness < 0, got: %v", err)
		}
	})

	t.Run("custom max staleness", func(t *testing.T) {
		ts, _ := switchableCRLServer(t, lateButTolerated)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, MaxStaleness: 24 * time.Hour, Now: clock})
		if _, err := s.Sync(context.Background()); !errors.Is(err, ErrCRLExpired) {
			t.Fatalf("expected ErrCRLExpired with 24h max staleness, got: %v", err)
		}
	})

	t.Run("strict expiry rejects any expired CRL", func(t *testing.T) {
		ts, _ := switchableCRLServer(t, lateButTolerated)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, StrictExpiry: true, Now: clock})
		if _, err := s.Sync(context.Background()); !errors.Is(err, ErrCRLExpired) {
			t.Fatalf("expected ErrCRLExpired with StrictExpiry, got: %v", err)
		}
	})

	t.Run("perpetual CRL never stale", func(t *testing.T) {
		ts, _ := switchableCRLServer(t, perpetual)
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, Now: clock})
		if _, err := s.Sync(context.Background()); err != nil {
			t.Fatalf("expected CRL without next_update to be accepted, got: %v", err)
		}
	})

	t.Run("stale cache fallback rejected but claims kept", func(t *testing.T) {
		cacheFile := filepath.Join(t.TempDir(), "crl.cache")
		if err := os.WriteFile(cacheFile, []byte(tooStale), 0644); err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := ts.URL
		ts.Close()
		s, _ := NewCRLSyncer(CRLSyncConfig{URL: url, KeyRing: ring, CacheFile: cacheFile, Now: clock})
		_, err := s.Sync(context.Background())
		if !errors.Is(err, ErrCRLExpired) {
			t.Fatalf("expected ErrCRLExpired for stale cache, got: %v", err)
		}
		if s.Claims() == nil || s.Claims().ID != "crl-stale" {
			t.Fatalf("stale cache claims should stay loaded for best-effort revocation checks")
		}
	})
}

func TestCRLSyncer_Freshness_StaleCopyIgnores304(t *testing.T) {
	pub, priv := generateCRLTestKeyPair(t)
	ring := NewKeyRing(pub)
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	tok := signVersionedCRL(t, priv, "crl-304-stale", 1, start, start.Add(24*time.Hour))
	var sawConditional atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			sawConditional.Store(true)
		}
		if r.Header.Get("If-None-Match") == "" && !sawConditional.Load() {
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(tok))
			return
		}
		// Misbehaving mirror: always claims "not modified".
		w.WriteHeader(http.StatusNotModified)
	}))
	defer ts.Close()

	s, _ := NewCRLSyncer(CRLSyncConfig{URL: ts.URL, KeyRing: ring, Now: clock})
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}
	res, err := s.Sync(context.Background())
	if err != nil || res.Source != SyncSourceNotModified {
		t.Fatalf("expected 304 while fresh, got %v / %v", res, err)
	}

	// Ten days later the trusted copy is stale: the syncer must stop revalidating conditionally,
	// and a 304 must not keep the stale CRL alive.
	now = start.Add(10 * 24 * time.Hour)
	sawConditional.Store(false)
	_, err = s.Sync(context.Background())
	if sawConditional.Load() {
		t.Fatalf("expected unconditional request once the trusted CRL is stale")
	}
	if !errors.Is(err, ErrCRLExpired) {
		t.Fatalf("expected ErrCRLExpired for stale CRL re-served, got: %v", err)
	}
}
