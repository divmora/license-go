package license

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultCRLSyncTimeout is the default HTTP request timeout for CRL synchronization.
const DefaultCRLSyncTimeout = 10 * time.Second

// DefaultCRLMaxDownloadBytes limits the maximum downloaded CRL payload to 10MB to defend against memory exhaustion.
const DefaultCRLMaxDownloadBytes int64 = 10 * 1024 * 1024

// DefaultCRLMaxStaleness is how long past its NextUpdate cutoff a remote, mirrored or cached CRL is still
// accepted by CRLSyncer when StrictExpiry is off. It tolerates a late publish or a short outage of the
// distribution point, but stops a mirror from serving one signed CRL indefinitely.
const DefaultCRLMaxStaleness = 7 * 24 * time.Hour

// DefaultCRLSyncUserAgent is the default HTTP User-Agent sent by CRLSyncer.
const DefaultCRLSyncUserAgent = "divmora-license-go/crl-syncer"

// SyncSource identifies the provenance of the revocation claims returned by a sync cycle.
type SyncSource string

const (
	// SyncSourceRemote indicates fresh revocation claims fetched and verified from the remote distribution endpoint.
	SyncSourceRemote SyncSource = "remote"

	// SyncSourceNotModified indicates the remote endpoint returned HTTP 304 Not Modified; existing in-memory claims preserved.
	SyncSourceNotModified SyncSource = "not_modified"

	// SyncSourceCache indicates a network or server failure occurred and verified claims were loaded from local disk cache.
	SyncSourceCache SyncSource = "cache"
)

// CRLSyncConfig defines configuration parameters for dynamic CRL synchronization.
type CRLSyncConfig struct {
	// URL is the remote HTTP/HTTPS endpoint hosting the CRL token or armored PEM file. (Required or resolved)
	URL string

	// KeyRing contains the trusted public keys used to cryptographically verify the downloaded CRL. (Required)
	KeyRing *KeyRing

	// CacheFile specifies a local filesystem path to persist verified CRLs for offline/air-gap resilience.
	CacheFile string

	// HTTPClient allows injecting a custom *http.Client (e.g. for mTLS, proxy, or custom timeouts).
	HTTPClient *http.Client

	// Timeout specifies the HTTP request timeout. Defaults to 10 seconds.
	Timeout time.Duration

	// StrictExpiry rejects CRLs whose NextUpdate has passed relative to local evaluation time.
	// It is equivalent to a zero MaxStaleness.
	StrictExpiry bool

	// MaxStaleness bounds how long past NextUpdate a downloaded, 304-revalidated or cached CRL is accepted.
	// Zero selects DefaultCRLMaxStaleness (7 days). A negative value disables the check and restores the
	// pre-v1.4.2 behaviour of trusting an expired CRL indefinitely (not recommended). CRLs without a
	// NextUpdate never go stale. Ignored when StrictExpiry is set.
	MaxStaleness time.Duration

	// Now overrides the clock used for freshness checks (e.g. to plug in an authoritative time source).
	// Defaults to time.Now.
	Now func() time.Time

	// MaxDownloadBytes limits the maximum allowable response body size. Defaults to 10MB.
	MaxDownloadBytes int64

	// UserAgent configures the HTTP User-Agent header. Defaults to DefaultCRLSyncUserAgent.
	UserAgent string

	// ExpectedProduct asserts that the verified CRL product scope matches this product name.
	ExpectedProduct string
}

// SyncResult details the outcome of a synchronization cycle.
type SyncResult struct {
	// Claims contains the unpacked and cryptographically verified revocation list claims.
	Claims *RevocationListClaims

	// Source identifies whether claims originated from a fresh remote download, HTTP 304, or disk cache fallback.
	Source SyncSource

	// ETag is the HTTP entity tag returned by the remote distribution point, if present.
	ETag string

	// LastModified is the HTTP Last-Modified timestamp string returned by the server, if present.
	LastModified string

	// NetworkError is populated when the remote request failed and the syncer fell back to local disk cache.
	NetworkError error
}

// CRLSyncer manages remote fetching, HTTP conditional caching (ETag/304),
// Ed25519 cryptographic verification, and atomic disk persistence of Certificate Revocation Lists.
type CRLSyncer struct {
	cfg          CRLSyncConfig
	mu           sync.RWMutex
	lastETag     string
	lastModified string
	cachedClaims *RevocationListClaims
	rawContent   string
	lastSyncTime time.Time
}

// NewCRLSyncer initializes a new CRLSyncer, asserting required configuration parameters.
func NewCRLSyncer(cfg CRLSyncConfig) (*CRLSyncer, error) {
	if cfg.KeyRing == nil || cfg.KeyRing.Count() == 0 {
		return nil, ErrMissingPublicKey
	}

	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		url = ResolveCRLURL(cfg.ExpectedProduct)
	}
	cfg.URL = url

	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultCRLSyncTimeout
	}
	if cfg.MaxDownloadBytes <= 0 {
		cfg.MaxDownloadBytes = DefaultCRLMaxDownloadBytes
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultCRLSyncUserAgent
	}
	if cfg.MaxStaleness == 0 {
		cfg.MaxStaleness = DefaultCRLMaxStaleness
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	syncer := &CRLSyncer{
		cfg: cfg,
	}

	// If a local cache file exists, eagerly load it to pre-populate in-memory claims
	if cfg.CacheFile != "" {
		if claims, raw, err := syncer.loadCacheFile(cfg.CacheFile); err == nil && claims != nil && syncer.checkProduct(claims) == nil {
			syncer.cachedClaims = claims
			syncer.rawContent = raw
		}
	}

	return syncer, nil
}

// Sync performs a synchronization cycle against the remote CRL distribution point.
// Uses HTTP conditional headers (If-None-Match, If-Modified-Since) to minimize bandwidth.
// If the remote server is unreachable, automatically falls back to local disk cache.
//
// A downloaded CRL is only accepted if it is at least as new (by Sequence, then IssuedAt) as the CRL
// already trusted in memory or in the cache file; an older one fails with ErrCRLRollback. CRLs past
// NextUpdate by more than MaxStaleness (or at all, with StrictExpiry) fail with ErrCRLExpired. On any
// rejection the previously trusted CRL stays in memory and on disk.
func (s *CRLSyncer) Sync(ctx context.Context) (*SyncResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.RLock()
	currentETag := s.lastETag
	currentModified := s.lastModified
	currentClaims := s.cachedClaims
	s.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return s.handleFallback(fmt.Errorf("failed to create http request: %w", err))
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)
	// Only revalidate conditionally while the trusted copy is still fresh; once it is stale,
	// ask for the full body so a 304 cannot keep an expired CRL alive.
	if s.freshnessError(currentClaims) == nil {
		if currentETag != "" {
			req.Header.Set("If-None-Match", CanonicalETag(currentETag))
		}
		if currentModified != "" {
			req.Header.Set("If-Modified-Since", currentModified)
		}
	}

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return s.handleFallback(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 1. HTTP 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		s.mu.Lock()
		s.lastSyncTime = time.Now().UTC()
		s.mu.Unlock()

		if currentClaims != nil {
			if err := s.freshnessError(currentClaims); err != nil {
				return nil, fmt.Errorf("%w (remote answered 304 Not Modified)", err)
			}
			return &SyncResult{
				Claims:       currentClaims,
				Source:       SyncSourceNotModified,
				ETag:         currentETag,
				LastModified: currentModified,
			}, nil
		}
		// In-memory claims were empty; try reloading from cache file
		return s.handleFallback(nil)
	}

	// 2. HTTP Non-200 Error
	if resp.StatusCode != http.StatusOK {
		httpErr := &CRLSyncError{
			URL:        s.cfg.URL,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("remote server returned HTTP %d", resp.StatusCode),
		}
		return s.handleFallback(httpErr)
	}

	// 3. HTTP 200 OK: Read payload with size guard
	lr := io.LimitReader(resp.Body, s.cfg.MaxDownloadBytes+1)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return s.handleFallback(fmt.Errorf("failed to read crl response body: %w", err))
	}
	if int64(len(bodyBytes)) > s.cfg.MaxDownloadBytes {
		return s.handleFallback(&CRLSyncError{
			URL:        s.cfg.URL,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("crl response exceeded maximum size limit (%d bytes)", s.cfg.MaxDownloadBytes),
		})
	}

	rawCRL := string(bodyBytes)

	// 4. Cryptographically verify signature against KeyRing
	verifiedClaims, _, err := VerifyCRL(rawCRL, s.cfg.KeyRing)
	if err != nil {
		// Digital signature or token format is invalid; do NOT update cache or state!
		return nil, fmt.Errorf("%w: downloaded crl failed verification: %v", ErrInvalidCRL, err)
	}

	// 5. Product scope assertion
	if err := s.checkProduct(verifiedClaims); err != nil {
		return nil, err
	}

	// 6. Rollback protection: never move backwards from the newest CRL already trusted,
	// whether it is held in memory or persisted in the cache file (possibly by another process).
	trusted := currentClaims
	if s.cfg.CacheFile != "" {
		if cacheClaims, _, err := s.loadCacheFile(s.cfg.CacheFile); err == nil && s.checkProduct(cacheClaims) == nil {
			if CompareCRLVersion(cacheClaims, trusted) > 0 {
				trusted = cacheClaims
			}
		}
	}
	if err := CheckCRLRollback(verifiedClaims, trusted); err != nil {
		return nil, fmt.Errorf("downloaded crl from %s rejected: %w", s.cfg.URL, err)
	}

	// 7. Freshness check (StrictExpiry, or NextUpdate + MaxStaleness)
	if err := s.freshnessError(verifiedClaims); err != nil {
		return nil, fmt.Errorf("downloaded crl from %s rejected: %w", s.cfg.URL, err)
	}

	newETag := CanonicalETag(resp.Header.Get("ETag"))
	newModified := resp.Header.Get("Last-Modified")

	s.mu.Lock()
	// Re-check under the lock in case a concurrent Sync adopted a newer CRL meanwhile.
	if err := CheckCRLRollback(verifiedClaims, s.cachedClaims); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("downloaded crl from %s rejected: %w", s.cfg.URL, err)
	}

	// 8. Atomic persistence to local disk cache (if configured)
	if s.cfg.CacheFile != "" {
		if err := atomicWriteFile(s.cfg.CacheFile, bodyBytes, 0644); err != nil {
			// Log/record cache write error, but return verified claims since memory is authoritative
			_ = err
		}
	}

	s.lastETag = newETag
	s.lastModified = newModified
	s.cachedClaims = verifiedClaims
	s.rawContent = rawCRL
	s.lastSyncTime = time.Now().UTC()
	s.mu.Unlock()

	return &SyncResult{
		Claims:       verifiedClaims,
		Source:       SyncSourceRemote,
		ETag:         newETag,
		LastModified: newModified,
	}, nil
}

// Claims returns the currently active, verified RevocationListClaims, or nil if none loaded.
func (s *CRLSyncer) Claims() *RevocationListClaims {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cachedClaims
}

// Raw returns the currently active raw CRL token string.
func (s *CRLSyncer) Raw() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rawContent
}

// LastSyncTime returns the timestamp when synchronization last succeeded.
func (s *CRLSyncer) LastSyncTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSyncTime
}

// URL returns the configured remote distribution point.
func (s *CRLSyncer) URL() string {
	return s.cfg.URL
}

// CacheFile returns the configured local cache file path.
func (s *CRLSyncer) CacheFile() string {
	return s.cfg.CacheFile
}

// handleFallback attempts to load and verify the local disk cache when remote sync fails.
func (s *CRLSyncer) handleFallback(origErr error) (*SyncResult, error) {
	if s.cfg.CacheFile == "" {
		if origErr != nil {
			return nil, &CRLSyncError{
				URL: s.cfg.URL,
				Err: fmt.Errorf("%w: remote fetch failed and no cache configured: %v", ErrCRLSyncFailed, origErr),
			}
		}
		return nil, ErrCRLSyncFailed
	}

	claims, raw, err := s.loadCacheFile(s.cfg.CacheFile)
	if err == nil {
		err = s.checkProduct(claims)
	}
	if err != nil {
		if origErr != nil {
			return nil, &CRLSyncError{
				URL: s.cfg.URL,
				Err: fmt.Errorf("%w: remote fetch failed (%v) and cache unavailable (%v)", ErrCRLSyncFailed, origErr, err),
			}
		}
		return nil, fmt.Errorf("%w: failed to read cache: %v", ErrCRLSyncFailed, err)
	}

	// Rollback protection: a cache file older than the in-memory copy (e.g. restored from a backup or
	// overwritten by another process) is ignored in favour of the newer in-memory CRL.
	s.mu.Lock()
	if CompareCRLVersion(claims, s.cachedClaims) < 0 {
		claims, raw = s.cachedClaims, s.rawContent
	}
	s.cachedClaims = claims
	s.rawContent = raw
	s.mu.Unlock()

	if err := s.freshnessError(claims); err != nil {
		return nil, fmt.Errorf("cached crl rejected: %w", err)
	}

	return &SyncResult{
		Claims:       claims,
		Source:       SyncSourceCache,
		NetworkError: origErr,
	}, nil
}

// freshnessError returns an error wrapping ErrCRLExpired if claims are too old to trust under the syncer's
// freshness policy: past NextUpdate with StrictExpiry, or past NextUpdate + MaxStaleness otherwise.
func (s *CRLSyncer) freshnessError(claims *RevocationListClaims) error {
	if claims == nil {
		return nil
	}
	now := s.cfg.Now().UTC()
	if s.cfg.StrictExpiry {
		if claims.IsExpiredAt(now) {
			return fmt.Errorf("%w: crl %q next_update %s has passed", ErrCRLExpired,
				claims.ID, claims.NextUpdate.UTC().Format(time.RFC3339))
		}
		return nil
	}
	if claims.IsStaleAt(now, s.cfg.MaxStaleness) {
		return fmt.Errorf("%w: crl %q next_update %s passed more than %s ago", ErrCRLExpired,
			claims.ID, claims.NextUpdate.UTC().Format(time.RFC3339), s.cfg.MaxStaleness)
	}
	return nil
}

// checkProduct asserts that the CRL product scope matches the configured ExpectedProduct.
func (s *CRLSyncer) checkProduct(claims *RevocationListClaims) error {
	if s.cfg.ExpectedProduct == "" || claims == nil || claims.Product == "" || claims.Product == "*" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(claims.Product), strings.TrimSpace(s.cfg.ExpectedProduct)) {
		return fmt.Errorf("%w: crl product %q does not match expected product %q",
			ErrProductMismatch, claims.Product, s.cfg.ExpectedProduct)
	}
	return nil
}

// loadCacheFile reads and cryptographically verifies a CRL file from disk.
func (s *CRLSyncer) loadCacheFile(filePath string) (*RevocationListClaims, string, error) {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return nil, "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("%w: cache file %s is a symlink", ErrSymlinkNotAllowed, filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, "", err
	}

	raw := string(data)
	claims, _, err := VerifyCRL(raw, s.cfg.KeyRing)
	if err != nil {
		return nil, "", err
	}

	return claims, raw, nil
}

// atomicWriteFile safely writes data to target path using a temporary file and atomic rename,
// preventing partial writes or corrupt state across processes.
func atomicWriteFile(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Disallow writing through symlinks
	if fi, err := os.Lstat(targetPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: target cache file %s is a symlink", ErrSymlinkNotAllowed, targetPath)
	}

	tmpFile, err := os.CreateTemp(dir, ".crl-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write temp cache: %w", err)
	}

	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("failed to chmod temp cache: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp cache: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp cache: %w", err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("failed to atomically rename cache file: %w", err)
	}

	return nil
}
