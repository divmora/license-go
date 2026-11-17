package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEC2Env points DMI and IMDS lookups at test fixtures and clears the
// detection cache before and after the test.
func fakeEC2Env(t *testing.T, dmi map[string]string, imdsURL string) {
	t.Helper()
	dir := t.TempDir()
	for name, val := range dmi {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	origDMI, origURL, origK8s := dmiDir, ec2ProbeBaseURL, k8sServiceAccountDir
	dmiDir, ec2ProbeBaseURL = dir, imdsURL
	k8sServiceAccountDir = filepath.Join(dir, "no-k8s")
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("AWS_LAMBDA_FUNCTION_ARN", "")
	ResetDetectionCache()
	t.Cleanup(func() {
		dmiDir, ec2ProbeBaseURL, k8sServiceAccountDir = origDMI, origURL, origK8s
		ResetDetectionCache()
	})
}

// closedURL returns the URL of a server that is already shut down, so any
// connection attempt fails immediately.
func closedURL(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.NotFoundHandler())
	u := ts.URL
	ts.Close()
	return u
}

// fakeIMDS serves IMDSv2 token and identity document. delay(n) returns how long
// to stall the n-th token request (1-based) before answering.
func fakeIMDS(t *testing.T, delay func(n int64) time.Duration) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var tokenHits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			n := tokenHits.Add(1)
			if d := delay(n); d > 0 {
				select {
				case <-time.After(d):
				case <-r.Context().Done():
					return
				}
			}
			_, _ = w.Write([]byte("tok"))
		case "/latest/dynamic/instance-identity/document":
			_ = json.NewEncoder(w).Encode(ec2IdentityDocument{
				InstanceID: "i-0abc1234def567890",
				AccountID:  "123456789012",
				Region:     "eu-west-1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &tokenHits
}

func TestIsLikelyAWSEC2_DMISignals(t *testing.T) {
	cases := []struct {
		name string
		dmi  map[string]string
		want bool
	}{
		{"nitro sys_vendor", map[string]string{"sys_vendor": "Amazon EC2"}, true},
		{"nitro bios_vendor", map[string]string{"bios_vendor": "Amazon EC2"}, true},
		{"nitro board_asset_tag", map[string]string{"board_asset_tag": "i-0abc1234def567890"}, true},
		{"xen product_uuid", map[string]string{"product_uuid": "EC2E1916-9099-7CAF-FD21-012345ABCDEF"}, true},
		{"xen bios_version", map[string]string{"bios_version": "4.11.amazon"}, true},
		{"other cloud", map[string]string{"sys_vendor": "Google", "board_asset_tag": "Not Specified"}, false},
		{"no dmi", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeEC2Env(t, tc.dmi, closedURL(t))
			if got := IsLikelyAWSEC2(); got != tc.want {
				t.Fatalf("IsLikelyAWSEC2() = %v, want %v", got, tc.want)
			}
		})
	}
}

// IMDS answering in 300 ms used to be classified as "not EC2" by the old 100 ms probe.
func TestIsLikelyAWSEC2_SlowIMDSStillDetected(t *testing.T) {
	ts, _ := fakeIMDS(t, func(int64) time.Duration { return 300 * time.Millisecond })
	fakeEC2Env(t, nil, ts.URL)
	if !IsLikelyAWSEC2() {
		t.Fatal("slow IMDS (300ms) should still be detected as EC2")
	}
}

func TestIsLikelyAWSEC2_RetriesTimedOutProbe(t *testing.T) {
	ts, hits := fakeIMDS(t, func(n int64) time.Duration {
		if n == 1 {
			return ec2ProbeTimeout + 500*time.Millisecond
		}
		return 0
	})
	fakeEC2Env(t, nil, ts.URL)
	if !IsLikelyAWSEC2() {
		t.Fatal("a single timed-out IMDS probe should be retried")
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 probe attempts, got %d", hits.Load())
	}
}

// Detection runs once per process: later IMDS stalls cannot flip the answer.
func TestIsLikelyAWSEC2_CachedForProcessLifetime(t *testing.T) {
	ts, hits := fakeIMDS(t, func(n int64) time.Duration {
		if n == 1 {
			return 0
		}
		return 5 * time.Second // would time out if probed again
	})
	fakeEC2Env(t, nil, ts.URL)
	for i := 0; i < 20; i++ {
		if !IsLikelyAWSEC2() {
			t.Fatalf("call %d: detection flipped to not-EC2", i)
		}
		if got := DetectEnvironment(); got != PlatformAWSEC2 {
			t.Fatalf("call %d: DetectEnvironment() = %s, want %s", i, got, PlatformAWSEC2)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected exactly 1 IMDS probe, got %d", hits.Load())
	}
}

func TestIsLikelyAWSEC2_NegativeResultCached(t *testing.T) {
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden) // definitive: no retry
	}))
	defer ts.Close()
	fakeEC2Env(t, nil, ts.URL)
	for i := 0; i < 5; i++ {
		if IsLikelyAWSEC2() {
			t.Fatal("HTTP 403 from IMDS must not be detected as EC2")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 probe (no retry on 403, then cached), got %d", hits.Load())
	}
}

func TestAWSEC2Resolver_RetriesTransientFailures(t *testing.T) {
	t.Run("timeout then success", func(t *testing.T) {
		ts, hits := fakeIMDS(t, func(n int64) time.Duration {
			if n == 1 {
				return 2 * time.Second
			}
			return 0
		})
		r := NewAWSEC2Resolver(WithAWSEC2BaseURL(ts.URL), WithAWSEC2Timeout(200*time.Millisecond))
		fp, err := r.Resolve(context.Background())
		if err != nil {
			t.Fatalf("expected retry to succeed, got %v", err)
		}
		if fp.Platform != PlatformAWSEC2 || hits.Load() != 2 {
			t.Fatalf("platform=%s hits=%d", fp.Platform, hits.Load())
		}
	})

	t.Run("503 then success", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/api/token" {
				if hits.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte("tok"))
				return
			}
			_ = json.NewEncoder(w).Encode(ec2IdentityDocument{InstanceID: "i-1"})
		}))
		defer ts.Close()
		fp, err := NewAWSEC2Resolver(WithAWSEC2BaseURL(ts.URL)).Resolve(context.Background())
		if err != nil || fp.Components["instance_id"] != "i-1" {
			t.Fatalf("expected success after 503, got fp=%v err=%v", fp, err)
		}
	})

	t.Run("403 is not retried", func(t *testing.T) {
		var hits atomic.Int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()
		if _, err := NewAWSEC2Resolver(WithAWSEC2BaseURL(ts.URL)).Resolve(context.Background()); err == nil {
			t.Fatal("expected error on 403")
		}
		if hits.Load() != 1 {
			t.Fatalf("expected 1 attempt on 403, got %d", hits.Load())
		}
	})

	t.Run("attempts option", func(t *testing.T) {
		ts, hits := fakeIMDS(t, func(int64) time.Duration { return time.Second })
		r := NewAWSEC2Resolver(WithAWSEC2BaseURL(ts.URL), WithAWSEC2Timeout(50*time.Millisecond), WithAWSEC2Attempts(1))
		if _, err := r.Resolve(context.Background()); err == nil {
			t.Fatal("expected timeout error")
		}
		if hits.Load() != 1 {
			t.Fatalf("expected 1 attempt, got %d", hits.Load())
		}
	})
}

// A licence bound to the host identity must keep matching on EC2, and vice versa.
func TestAWSEC2Resolver_HostAlternateMatches(t *testing.T) {
	ts, _ := fakeIMDS(t, func(int64) time.Duration { return 0 })
	fp, err := NewAWSEC2Resolver(WithAWSEC2BaseURL(ts.URL)).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	host, err := ResolveHostFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(fp.Alternates) != 1 || fp.Alternates[0].Primary != host.Primary {
		t.Fatalf("expected host alternate %q, got %+v", host.Primary, fp.Alternates)
	}
	if !fp.Matches(host.Primary) {
		t.Errorf("EC2 fingerprint must match host-bound licence %q", host.Primary)
	}
	if !fp.Matches(fp.Primary) {
		t.Errorf("EC2 fingerprint must match its own primary")
	}
	if fp.Matches("fp:host:0000000000000000") || fp.Matches("fp:aws:0000000000000000") {
		t.Error("unrelated fingerprints must not match")
	}
}

// Reproduces divmora/gitlab-fleet-governor#98: IMDS alternates between fast and
// stalled responses. The default resolver must return the same identity every time.
func TestDefaultComposite_StableUnderFlakyIMDS(t *testing.T) {
	ts, _ := fakeIMDS(t, func(n int64) time.Duration {
		if n%2 == 1 {
			return defaultEC2Timeout + 500*time.Millisecond
		}
		return 0
	})
	fakeEC2Env(t, map[string]string{"sys_vendor": "Amazon EC2"}, ts.URL)

	resolve := func() *MachineFingerprint {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // same budget as the validator
		defer cancel()
		fp, err := NewDefaultCompositeResolver().Resolve(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}

	first := resolve()
	if first.Platform != PlatformAWSEC2 {
		t.Fatalf("expected aws-ec2, got %s (%s)", first.Platform, first.Primary)
	}
	// Without the process cache, retries alone keep the identity stable.
	for i := 0; i < 3; i++ {
		resetDefaultFingerprintCache()
		if got := resolve(); got.Primary != first.Primary {
			t.Fatalf("uncached call %d: fingerprint flipped %s -> %s", i, first.Primary, got.Primary)
		}
	}
	// With the process cache, IMDS is not consulted again at all.
	ts.Close()
	for i := 0; i < 5; i++ {
		if got := resolve(); got.Primary != first.Primary {
			t.Fatalf("cached call %d: fingerprint flipped %s -> %s", i, first.Primary, got.Primary)
		}
	}
}

func TestDefaultComposite_SkipsIMDSWhenNotEC2(t *testing.T) {
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()
	fakeEC2Env(t, nil, ts.URL)

	for i := 0; i < 5; i++ {
		fp, err := NewDefaultCompositeResolver().Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if fp.Platform != PlatformHost {
			t.Fatalf("expected host, got %s", fp.Platform)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected only the single cached detection probe, got %d IMDS hits", hits.Load())
	}
}

func TestMachineFingerprint_CloneIsDeep(t *testing.T) {
	fp := &MachineFingerprint{
		Primary:    "fp:aws:1",
		Components: map[string]string{"a": "b"},
		Alternates: []MachineFingerprint{{Primary: "fp:host:2", Components: map[string]string{"c": "d"}}},
	}
	c := fp.clone()
	c.Components["a"] = "x"
	c.Alternates[0].Components["c"] = "y"
	if fp.Components["a"] != "b" || fp.Alternates[0].Components["c"] != "d" {
		t.Fatal("clone shares state with the original")
	}
	if (*MachineFingerprint)(nil).clone() != nil {
		t.Fatal("nil clone should be nil")
	}
}
