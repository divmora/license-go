package resolvers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	defaultK8sServiceAcctDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultK8sAPIBaseURL     = "https://kubernetes.default.svc"
	defaultK8sTimeout        = 1 * time.Second
	defaultK8sAttempts       = 3
)

// Process-wide cache of kube-system UIDs read from the API server, keyed by
// API URL, serviceaccount directory and cluster CA hash. Once a process has
// read the authoritative UID, a later API outage or throttling cannot switch
// the fingerprint to the CA-hash fallback.
var (
	k8sUIDCacheMu sync.Mutex
	k8sUIDCache   = map[string]string{}
)

func resetK8sUIDCache() {
	k8sUIDCacheMu.Lock()
	k8sUIDCache = map[string]string{}
	k8sUIDCacheMu.Unlock()
}

// KubernetesOption configures a KubernetesResolver.
type KubernetesOption func(*KubernetesResolver)

// WithKubernetesServiceAccountDir sets the serviceaccount secret directory.
func WithKubernetesServiceAccountDir(dir string) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.serviceAccountDir = dir
	}
}

// WithKubernetesAPIBaseURL sets the Kubernetes API server base URL.
func WithKubernetesAPIBaseURL(rawURL string) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.apiBaseURL = strings.TrimRight(rawURL, "/")
	}
}

// WithKubernetesHTTPClient sets a custom HTTP client for Kubernetes API requests.
func WithKubernetesHTTPClient(client *http.Client) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.httpClient = client
	}
}

// WithKubernetesTimeout sets the timeout for Kubernetes API requests.
func WithKubernetesTimeout(d time.Duration) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.timeout = d
	}
}

// WithKubernetesClusterID sets an explicit cluster ID to bypass API server discovery.
func WithKubernetesClusterID(id string) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.clusterID = strings.TrimSpace(id)
	}
}

// WithAllowInsecureNamespaceClusterID permits falling back to 'ns:<namespace>' when cluster identity
// cannot be uniquely established.
func WithAllowInsecureNamespaceClusterID(allow bool) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.allowInsecureNamespaceClusterID = allow
	}
}

// WithKubernetesAttempts sets how many times the kube-system namespace lookup is
// attempted (minimum 1). Timeouts, HTTP 429 and HTTP 5xx are retried; RBAC
// denials (401/403) are not.
func WithKubernetesAttempts(n int) KubernetesOption {
	return func(r *KubernetesResolver) {
		if n < 1 {
			n = 1
		}
		r.attempts = n
	}
}

// KubernetesResolver inspects Kubernetes in-cluster secrets and API to extract cluster identity.
type KubernetesResolver struct {
	attempts                        int
	serviceAccountDir               string
	apiBaseURL                      string
	httpClient                      *http.Client
	timeout                         time.Duration
	clusterID                       string
	allowInsecureNamespaceClusterID bool
}

// NewKubernetesResolver constructs a new KubernetesResolver with optional configuration.
func NewKubernetesResolver(opts ...KubernetesOption) *KubernetesResolver {
	r := &KubernetesResolver{
		serviceAccountDir: defaultK8sServiceAcctDir,
		apiBaseURL:        defaultK8sAPIBaseURL,
		timeout:           defaultK8sTimeout,
		attempts:          defaultK8sAttempts,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Name returns the descriptive name of the resolver.
func (r *KubernetesResolver) Name() string {
	return "kubernetes-cluster"
}

// Platform returns PlatformKubernetes.
func (r *KubernetesResolver) Platform() Platform {
	return PlatformKubernetes
}

type k8sNamespaceMetadata struct {
	Metadata struct {
		UID  string `json:"uid"`
		Name string `json:"name"`
	} `json:"metadata"`
}

// hasValidServiceAccountDir verifies whether a candidate serviceaccount directory
// contains non-empty cryptographic credentials (ca.crt, token, or namespace).
func hasValidServiceAccountDir(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	for _, file := range []string{"ca.crt", "token", "namespace"} {
		p := filepath.Join(dir, file)
		if sfi, err := os.Stat(p); err == nil && !sfi.IsDir() && sfi.Size() > 0 {
			return true
		}
	}
	return false
}

// Resolve evaluates in-cluster credentials and cluster UID to return a MachineFingerprint.
func (r *KubernetesResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	// 1. Detect if running within Kubernetes
	hasSvcAcct := hasValidServiceAccountDir(r.serviceAccountDir)
	hasExplicitClusterID := r.clusterID != ""

	// An unauthenticated environment variable (KUBERNETES_CLUSTER_ID, CLUSTER_UID, or KUBERNETES_SERVICE_HOST)
	// must NEVER bypass the in-cluster execution guard on non-Kubernetes hosts.
	if !hasSvcAcct && !hasExplicitClusterID {
		return nil, errors.New("kubernetes: not running inside a kubernetes cluster")
	}

	components := make(map[string]string)
	components["os"] = runtime.GOOS
	components["arch"] = runtime.GOARCH

	// 2. Discover namespace
	var namespace string
	nsPath := filepath.Join(r.serviceAccountDir, "namespace")
	if data, err := os.ReadFile(nsPath); err == nil {
		namespace = strings.TrimSpace(string(data))
	}
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	if namespace != "" {
		components["namespace"] = namespace
	}

	// Hostname / Pod / Node details
	if pod := os.Getenv("POD_NAME"); pod != "" {
		components["pod_name"] = pod
	} else if host, err := os.Hostname(); err == nil && host != "" {
		components["pod_name"] = host
	}
	if node := os.Getenv("NODE_NAME"); node != "" {
		components["node_name"] = node
	} else if node := os.Getenv("KUBE_NODE_NAME"); node != "" {
		components["node_name"] = node
	}

	// Extract in-cluster serviceaccount ca.crt to compute stable cryptographic cluster CA anchor
	caPath := filepath.Join(r.serviceAccountDir, "ca.crt")
	var caHash string
	if caData, err := os.ReadFile(caPath); err == nil && len(caData) > 0 {
		sum := sha256.Sum256(caData)
		caHash = hex.EncodeToString(sum[:])
		components["cluster_ca_hash"] = caHash
	}

	// Extract token issuer claim (iss) from in-cluster ServiceAccount token if present
	tokenPath := filepath.Join(r.serviceAccountDir, "token")
	if tokenData, err := os.ReadFile(tokenPath); err == nil && len(tokenData) > 0 {
		if iss := extractJWTIssuer(string(tokenData)); iss != "" {
			components["token_issuer"] = iss
		}
	}

	// 3. Resolve cluster UID
	clusterUID := r.clusterID

	// If no explicit cluster ID was configured programmatically, use the authoritative
	// immutable kube-system namespace UID from the API (cached per process, retried on
	// transient errors).
	fromAPI := false
	if clusterUID == "" {
		if uid := r.kubeSystemUID(ctx, caHash); uid != "" {
			clusterUID = uid
			fromAPI = true
		}
	}

	// The identity this pod would get if the API lookup were unavailable.
	fallbackUID := r.fallbackClusterUID(namespace, caHash)
	if clusterUID == "" {
		clusterUID = fallbackUID
	}
	if clusterUID == "" {
		return nil, fmt.Errorf("kubernetes: unable to establish unique cluster identity (kube-system UID inaccessible via RBAC and ca.crt unavailable); configure KUBERNETES_CLUSTER_ID or grant view access to kube-system namespace")
	}

	var alternates []MachineFingerprint
	if fromAPI && fallbackUID != "" && fallbackUID != clusterUID {
		alt := make(map[string]string, len(components)+1)
		for k, v := range components {
			alt[k] = v
		}
		alt["cluster_uid"] = fallbackUID
		alternates = append(alternates, newK8sFingerprint(alt))
	}

	components["cluster_uid"] = clusterUID

	fp := newK8sFingerprint(components)
	fp.Alternates = alternates
	return &fp, nil
}

func newK8sFingerprint(components map[string]string) MachineFingerprint {
	digest, short := ComputeCanonicalDigest(PlatformKubernetes, components)
	return MachineFingerprint{
		Primary:         fmt.Sprintf("fp:k8s:%s", short),
		Platform:        PlatformKubernetes,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}
}

// fallbackClusterUID returns the cluster identity used when the kube-system UID
// cannot be read from the API: /etc/kubernetes/cluster-id, then the
// KUBERNETES_CLUSTER_ID / CLUSTER_UID env vars, then the cluster CA hash, then
// (only if explicitly allowed) the namespace.
func (r *KubernetesResolver) fallbackClusterUID(namespace, caHash string) string {
	if data, err := os.ReadFile("/etc/kubernetes/cluster-id"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	if id := os.Getenv("KUBERNETES_CLUSTER_ID"); id != "" {
		return id
	}
	if id := os.Getenv("CLUSTER_UID"); id != "" {
		return id
	}
	if caHash != "" {
		return "ca:" + caHash[:16]
	}
	if r.allowInsecureNamespaceClusterID && namespace != "" {
		return "ns:" + namespace
	}
	return ""
}

// kubeSystemUID returns the kube-system namespace UID, from the process cache
// when this cluster was already resolved, otherwise from the API with retries.
// It returns "" when the API is unreachable or access is denied.
func (r *KubernetesResolver) kubeSystemUID(ctx context.Context, caHash string) string {
	key := r.apiBaseURL + "|" + r.serviceAccountDir + "|" + caHash
	k8sUIDCacheMu.Lock()
	uid, ok := k8sUIDCache[key]
	k8sUIDCacheMu.Unlock()
	if ok {
		return uid
	}

	attempts := r.attempts
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ""
			case <-time.After(time.Duration(i) * retryBackoff):
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, r.timeout)
		uid, err := r.queryKubeSystemNamespaceUID(attemptCtx)
		cancel()
		if err == nil && uid != "" {
			k8sUIDCacheMu.Lock()
			k8sUIDCache[key] = uid
			k8sUIDCacheMu.Unlock()
			return uid
		}
		if !isRetryableHTTPError(err) || ctx.Err() != nil {
			break
		}
	}
	return ""
}

func (r *KubernetesResolver) queryKubeSystemNamespaceUID(ctx context.Context) (string, error) {
	tokenPath := filepath.Join(r.serviceAccountDir, "token")
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", &permanentError{fmt.Errorf("failed to read token: %w", err)}
	}
	token := strings.TrimSpace(string(tokenBytes))

	client := r.httpClient
	if client == nil {
		caPath := filepath.Join(r.serviceAccountDir, "ca.crt")
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if caData, err := os.ReadFile(caPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caData) {
				tlsConfig.RootCAs = pool
			}
		}
		client = &http.Client{
			Timeout: r.timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/kube-system", r.apiBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", &httpStatusError{code: resp.StatusCode, msg: fmt.Sprintf("kube-system API returned HTTP %d", resp.StatusCode)}
	}

	var ns k8sNamespaceMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&ns); err != nil {
		return "", err
	}

	if ns.Metadata.UID == "" {
		return "", &permanentError{errors.New("kube-system namespace missing uid")}
	}

	return ns.Metadata.UID, nil
}

func extractJWTIssuer(tokenStr string) string {
	parts := strings.Split(strings.TrimSpace(tokenStr), ".")
	if len(parts) < 2 {
		return ""
	}
	payloadSegment := parts[1]
	if m := len(payloadSegment) % 4; m != 0 {
		payloadSegment += strings.Repeat("=", 4-m)
	}
	payloadBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return ""
	}
	return strings.TrimSpace(claims.Iss)
}

// ResolveKubernetesFingerprint resolves the machine identity inside a Kubernetes cluster.
func ResolveKubernetesFingerprint() (*MachineFingerprint, error) {
	return NewKubernetesResolver().Resolve(context.Background())
}

// ResolveKubernetesFingerprintWithContext resolves the machine identity inside a Kubernetes cluster with context.
func ResolveKubernetesFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewKubernetesResolver().Resolve(ctx)
}
