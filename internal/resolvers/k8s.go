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
	"time"
)

const (
	defaultK8sServiceAcctDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultK8sAPIBaseURL     = "https://kubernetes.default.svc"
	defaultK8sTimeout        = 1 * time.Second
)

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

// KubernetesResolver inspects Kubernetes in-cluster secrets and API to extract cluster identity.
type KubernetesResolver struct {
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

// Resolve evaluates in-cluster credentials and cluster UID to return a MachineFingerprint.
func (r *KubernetesResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	// 1. Detect if running within Kubernetes
	hasSvcAcct := false
	if fi, err := os.Stat(r.serviceAccountDir); err == nil && fi.IsDir() {
		hasSvcAcct = true
	}
	hasHostEnv := os.Getenv("KUBERNETES_SERVICE_HOST") != ""
	hasEnvID := r.clusterID != "" || os.Getenv("KUBERNETES_CLUSTER_ID") != "" || os.Getenv("CLUSTER_UID") != ""

	if !hasSvcAcct && !hasHostEnv && !hasEnvID {
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

	// 3. Resolve cluster UID
	clusterUID := r.clusterID
	if clusterUID == "" {
		clusterUID = os.Getenv("KUBERNETES_CLUSTER_ID")
	}
	if clusterUID == "" {
		clusterUID = os.Getenv("CLUSTER_UID")
	}
	if clusterUID == "" {
		// Try reading /etc/kubernetes/cluster-id if available
		if data, err := os.ReadFile("/etc/kubernetes/cluster-id"); err == nil {
			clusterUID = strings.TrimSpace(string(data))
		}
	}

	// If cluster UID is still not found, try querying Kubernetes API for kube-system namespace UID
	if clusterUID == "" {
		uid, err := r.queryKubeSystemNamespaceUID(ctx)
		if err == nil && uid != "" {
			clusterUID = uid
		}
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

	// If cluster UID was not resolved from explicit config, env, /etc/kubernetes/cluster-id, or API,
	// anchor cluster identity to the unique cluster CA certificate hash to prevent universal namespace collisions.
	if clusterUID == "" && caHash != "" {
		clusterUID = "ca:" + caHash[:16]
	}

	// If still no cluster UID, check whether insecure namespace fallback was explicitly enabled
	if clusterUID == "" {
		if r.allowInsecureNamespaceClusterID && namespace != "" {
			clusterUID = "ns:" + namespace
		} else {
			return nil, fmt.Errorf("kubernetes: unable to establish unique cluster identity (kube-system UID inaccessible via RBAC and ca.crt unavailable); configure KUBERNETES_CLUSTER_ID or grant view access to kube-system namespace")
		}
	}

	components["cluster_uid"] = clusterUID

	digest, short := ComputeCanonicalDigest(PlatformKubernetes, components)

	return &MachineFingerprint{
		Primary:         fmt.Sprintf("fp:k8s:%s", short),
		Platform:        PlatformKubernetes,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}, nil
}

func (r *KubernetesResolver) queryKubeSystemNamespaceUID(ctx context.Context) (string, error) {
	tokenPath := filepath.Join(r.serviceAccountDir, "token")
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kube-system API returned HTTP %d", resp.StatusCode)
	}

	var ns k8sNamespaceMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&ns); err != nil {
		return "", err
	}

	if ns.Metadata.UID == "" {
		return "", errors.New("kube-system namespace missing uid")
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
