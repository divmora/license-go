package license

import (
	"context"
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
