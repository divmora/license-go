package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKubeSystemUID = "6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8"

// fakeServiceAccount writes namespace, token and ca.crt into a temp dir and
// clears the Kubernetes UID cache before and after the test.
func fakeServiceAccount(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"namespace": "fleet",
		"token":     "mock-token",
		"ca.crt":    "-----BEGIN CERTIFICATE-----\nMIICMockStabilityCA==\n-----END CERTIFICATE-----\n",
	}
	for name, val := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KUBERNETES_CLUSTER_ID", "")
	t.Setenv("CLUSTER_UID", "")
	resetK8sUIDCache()
	t.Cleanup(resetK8sUIDCache)
	return dir
}

// fakeKubeAPI serves the kube-system namespace. respond(n) decides the n-th
// request's (1-based) behaviour: a delay and an HTTP status (200 serves the UID).
func fakeKubeAPI(t *testing.T, respond func(n int64) (time.Duration, int)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/kube-system" {
			http.NotFound(w, r)
			return
		}
		delay, code := respond(hits.Add(1))
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		var ns k8sNamespaceMetadata
		ns.Metadata.UID = testKubeSystemUID
		ns.Metadata.Name = "kube-system"
		_ = json.NewEncoder(w).Encode(ns)
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

func newTestK8sResolver(dir string, ts *httptest.Server, opts ...KubernetesOption) *KubernetesResolver {
	base := []KubernetesOption{
		WithKubernetesServiceAccountDir(dir),
		WithKubernetesAPIBaseURL(ts.URL),
		WithKubernetesHTTPClient(ts.Client()),
		WithKubernetesTimeout(200 * time.Millisecond),
	}
	return NewKubernetesResolver(append(base, opts...)...)
}

func TestKubernetesResolver_RetriesTransientAPIFailures(t *testing.T) {
	cases := []struct {
		name    string
		respond func(n int64) (time.Duration, int)
	}{
		{"timeout then success", func(n int64) (time.Duration, int) {
			if n == 1 {
				return time.Second, http.StatusOK
			}
			return 0, http.StatusOK
		}},
		{"503 then success", func(n int64) (time.Duration, int) {
			if n == 1 {
				return 0, http.StatusServiceUnavailable
			}
			return 0, http.StatusOK
		}},
		{"429 then success", func(n int64) (time.Duration, int) {
			if n == 1 {
				return 0, http.StatusTooManyRequests
			}
			return 0, http.StatusOK
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := fakeServiceAccount(t)
			ts, hits := fakeKubeAPI(t, tc.respond)
			fp, err := newTestK8sResolver(dir, ts).Resolve(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if fp.Components["cluster_uid"] != testKubeSystemUID {
				t.Fatalf("expected API UID after retry, got %q", fp.Components["cluster_uid"])
			}
			if hits.Load() != 2 {
				t.Fatalf("expected 2 API attempts, got %d", hits.Load())
			}
		})
	}
}

// An RBAC denial is a definitive answer: no retry, CA-hash fallback as before.
func TestKubernetesResolver_ForbiddenNotRetried(t *testing.T) {
	dir := fakeServiceAccount(t)
	ts, hits := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusForbidden })
	fp, err := newTestK8sResolver(dir, ts).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp.Components["cluster_uid"], "ca:") {
		t.Fatalf("expected CA-hash fallback, got %q", fp.Components["cluster_uid"])
	}
	if len(fp.Alternates) != 0 {
		t.Fatalf("fallback identity needs no alternates, got %d", len(fp.Alternates))
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 API attempt on 403, got %d", hits.Load())
	}
}

func TestKubernetesResolver_AttemptsOption(t *testing.T) {
	dir := fakeServiceAccount(t)
	ts, hits := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusServiceUnavailable })
	if _, err := newTestK8sResolver(dir, ts, WithKubernetesAttempts(1)).Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 attempt, got %d", hits.Load())
	}
}

// Once the authoritative UID was read, API stalls and outages cannot change the fingerprint.
func TestKubernetesResolver_StableUnderFlakyAPI(t *testing.T) {
	dir := fakeServiceAccount(t)
	ts, hits := fakeKubeAPI(t, func(n int64) (time.Duration, int) {
		if n == 1 {
			return 0, http.StatusOK
		}
		return time.Second, http.StatusOK // would time out if called again
	})
	r := newTestK8sResolver(dir, ts)

	first, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Components["cluster_uid"] != testKubeSystemUID {
		t.Fatalf("expected API UID, got %q", first.Components["cluster_uid"])
	}
	for i := 0; i < 10; i++ {
		got, err := newTestK8sResolver(dir, ts).Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.Primary != first.Primary {
			t.Fatalf("call %d: fingerprint flipped %s -> %s", i, first.Primary, got.Primary)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected the API to be queried once, got %d", hits.Load())
	}
}

// A licence issued while the API was unavailable (CA-hash identity) must still
// match once the API answers, and vice versa.
func TestKubernetesResolver_FallbackIdentityIsAlternate(t *testing.T) {
	dir := fakeServiceAccount(t)

	down, _ := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusServiceUnavailable })
	fallback, err := newTestK8sResolver(dir, down).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fallback.Components["cluster_uid"], "ca:") {
		t.Fatalf("expected CA-hash identity while API is down, got %q", fallback.Components["cluster_uid"])
	}

	up, _ := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusOK })
	authoritative, err := newTestK8sResolver(dir, up).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if authoritative.Primary == fallback.Primary {
		t.Fatal("test setup: API and fallback identities should differ")
	}
	if len(authoritative.Alternates) != 1 || authoritative.Alternates[0].Primary != fallback.Primary {
		t.Fatalf("expected fallback identity %q as alternate, got %+v", fallback.Primary, authoritative.Alternates)
	}
	if !authoritative.Matches(fallback.Primary) {
		t.Errorf("API identity must match a licence bound to the fallback identity %q", fallback.Primary)
	}
	if !authoritative.Matches(authoritative.Primary) {
		t.Error("API identity must match its own primary")
	}
	if authoritative.Matches("fp:k8s:0000000000000000") {
		t.Error("unrelated fingerprint must not match")
	}
}

// An explicitly configured cluster ID never calls the API and needs no alternate.
func TestKubernetesResolver_ExplicitClusterIDSkipsAPI(t *testing.T) {
	dir := fakeServiceAccount(t)
	ts, hits := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusOK })
	fp, err := newTestK8sResolver(dir, ts, WithKubernetesClusterID("prod-eu-1")).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp.Components["cluster_uid"] != "prod-eu-1" || len(fp.Alternates) != 0 || hits.Load() != 0 {
		t.Fatalf("cluster_uid=%q alternates=%d hits=%d", fp.Components["cluster_uid"], len(fp.Alternates), hits.Load())
	}
}

func TestResetDetectionCache_ClearsK8sUIDs(t *testing.T) {
	dir := fakeServiceAccount(t)
	ts, hits := fakeKubeAPI(t, func(int64) (time.Duration, int) { return 0, http.StatusOK })
	for i := 0; i < 2; i++ {
		if _, err := newTestK8sResolver(dir, ts).Resolve(context.Background()); err != nil {
			t.Fatal(err)
		}
		ResetDetectionCache()
	}
	if hits.Load() != 2 {
		t.Fatalf("expected a fresh API lookup after reset, got %d hits", hits.Load())
	}
}
