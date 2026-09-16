package license

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
	defaultEC2BaseURL        = "http://169.254.169.254"
	defaultEC2Timeout        = 500 * time.Millisecond
	defaultK8sServiceAcctDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultK8sAPIBaseURL     = "https://kubernetes.default.svc"
	defaultK8sTimeout        = 1 * time.Second
)

// --- AWS EC2 Resolver ---

// AWSEC2Option configures an AWSEC2Resolver.
type AWSEC2Option func(*AWSEC2Resolver)

// WithAWSEC2BaseURL overrides the default IMDSv2 base URL (useful for testing).
func WithAWSEC2BaseURL(rawURL string) AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		r.baseURL = strings.TrimRight(rawURL, "/")
	}
}

// WithAWSEC2Timeout sets the HTTP timeout for IMDSv2 queries.
func WithAWSEC2Timeout(d time.Duration) AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		r.timeout = d
	}
}

// WithAWSEC2HTTPClient sets a custom http.Client for IMDSv2 queries.
func WithAWSEC2HTTPClient(client *http.Client) AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		r.httpClient = client
	}
}

// AWSEC2Resolver inspects AWS EC2 IMDSv2 metadata to extract instance identity.
type AWSEC2Resolver struct {
	baseURL    string
	timeout    time.Duration
	httpClient *http.Client
}

// NewAWSEC2Resolver creates a new AWSEC2Resolver with optional configuration.
func NewAWSEC2Resolver(opts ...AWSEC2Option) *AWSEC2Resolver {
	r := &AWSEC2Resolver{
		baseURL: defaultEC2BaseURL,
		timeout: defaultEC2Timeout,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.httpClient == nil {
		r.httpClient = &http.Client{
			Timeout: r.timeout,
		}
	}
	return r
}

// Name returns the descriptive name of the resolver.
func (r *AWSEC2Resolver) Name() string {
	return "aws-ec2-imds"
}

// Platform returns PlatformAWSEC2.
func (r *AWSEC2Resolver) Platform() Platform {
	return PlatformAWSEC2
}

type ec2IdentityDocument struct {
	InstanceID       string `json:"instanceId"`
	AccountID        string `json:"accountId"`
	Region           string `json:"region"`
	AvailabilityZone string `json:"availabilityZone"`
	InstanceType     string `json:"instanceType"`
	Architecture     string `json:"architecture"`
	ImageID          string `json:"imageId"`
}

// Resolve queries the IMDSv2 metadata endpoint and returns a MachineFingerprint.
func (r *AWSEC2Resolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	reqCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// 1. Obtain IMDSv2 session token
	tokenURL := fmt.Sprintf("%s/latest/api/token", r.baseURL)
	tokenReq, err := http.NewRequestWithContext(reqCtx, http.MethodPut, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("aws-ec2: failed to build token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	tokenResp, err := r.httpClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("aws-ec2: IMDSv2 token acquisition failed: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws-ec2: IMDSv2 token endpoint returned HTTP %d", tokenResp.StatusCode)
	}

	tokenBytes, err := io.ReadAll(io.LimitReader(tokenResp.Body, 1024))
	if err != nil {
		return nil, fmt.Errorf("aws-ec2: failed to read token response: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, errors.New("aws-ec2: received empty IMDSv2 token")
	}

	// 2. Query dynamic instance identity document
	docURL := fmt.Sprintf("%s/latest/dynamic/instance-identity/document", r.baseURL)
	docReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("aws-ec2: failed to build identity doc request: %w", err)
	}
	docReq.Header.Set("X-aws-ec2-metadata-token", token)

	docResp, err := r.httpClient.Do(docReq)
	if err != nil {
		return nil, fmt.Errorf("aws-ec2: failed to fetch instance identity document: %w", err)
	}
	defer docResp.Body.Close()

	if docResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws-ec2: instance identity endpoint returned HTTP %d", docResp.StatusCode)
	}

	var doc ec2IdentityDocument
	if err := json.NewDecoder(io.LimitReader(docResp.Body, 16384)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("aws-ec2: failed to decode instance identity document: %w", err)
	}

	if doc.InstanceID == "" {
		return nil, errors.New("aws-ec2: identity document missing instanceId")
	}

	components := make(map[string]string)
	components["os"] = runtime.GOOS
	components["arch"] = runtime.GOARCH
	components["instance_id"] = doc.InstanceID
	if doc.AccountID != "" {
		components["account_id"] = doc.AccountID
	}
	if doc.Region != "" {
		components["region"] = doc.Region
	}
	if doc.AvailabilityZone != "" {
		components["availability_zone"] = doc.AvailabilityZone
	}
	if doc.InstanceType != "" {
		components["instance_type"] = doc.InstanceType
	}
	if doc.ImageID != "" {
		components["image_id"] = doc.ImageID
	}

	digest, short := computeCanonicalDigest(PlatformAWSEC2, components)

	return &MachineFingerprint{
		Primary:         fmt.Sprintf("fp:aws:%s", short),
		Platform:        PlatformAWSEC2,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}, nil
}

// ResolveAWSEC2Fingerprint resolves the machine identity for an AWS EC2 instance.
func ResolveAWSEC2Fingerprint() (*MachineFingerprint, error) {
	return NewAWSEC2Resolver().Resolve(context.Background())
}

// ResolveAWSEC2FingerprintWithContext resolves the machine identity for an AWS EC2 instance with context.
func ResolveAWSEC2FingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewAWSEC2Resolver().Resolve(ctx)
}

// --- AWS Lambda Resolver ---

// AWSLambdaOption configures an AWSLambdaResolver.
type AWSLambdaOption func(*AWSLambdaResolver)

// WithAWSLambdaFunctionName explicitly sets the Lambda function name.
func WithAWSLambdaFunctionName(name string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.functionName = strings.TrimSpace(name)
	}
}

// WithAWSLambdaRegion explicitly sets the AWS region.
func WithAWSLambdaRegion(region string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.region = strings.TrimSpace(region)
	}
}

// WithAWSLambdaAccountID explicitly sets the AWS account ID.
func WithAWSLambdaAccountID(accountID string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.accountID = strings.TrimSpace(accountID)
	}
}

// WithAWSLambdaFunctionARN explicitly sets the full Lambda function ARN.
func WithAWSLambdaFunctionARN(arn string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.functionARN = strings.TrimSpace(arn)
	}
}

// WithAWSLambdaMemorySize explicitly sets the memory size in MB.
func WithAWSLambdaMemorySize(mb string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.memorySizeMB = strings.TrimSpace(mb)
	}
}

// WithAWSLambdaRuntime explicitly sets the execution runtime.
func WithAWSLambdaRuntime(rt string) AWSLambdaOption {
	return func(r *AWSLambdaResolver) {
		r.runtimeEnv = strings.TrimSpace(rt)
	}
}

// AWSLambdaResolver inspects AWS Lambda environment variables to extract function identity.
type AWSLambdaResolver struct {
	functionName string
	region       string
	accountID    string
	functionARN  string
	memorySizeMB string
	runtimeEnv   string
}

// NewAWSLambdaResolver constructs a new AWSLambdaResolver with optional overrides.
func NewAWSLambdaResolver(opts ...AWSLambdaOption) *AWSLambdaResolver {
	r := &AWSLambdaResolver{}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Name returns the descriptive name of the resolver.
func (r *AWSLambdaResolver) Name() string {
	return "aws-lambda-env"
}

// Platform returns PlatformAWSLambda.
func (r *AWSLambdaResolver) Platform() Platform {
	return PlatformAWSLambda
}

// Resolve evaluates AWS Lambda environment variables and returns a MachineFingerprint.
func (r *AWSLambdaResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	fnName := r.functionName
	if fnName == "" {
		fnName = strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_NAME"))
	}
	hasTaskRoot := strings.TrimSpace(os.Getenv("LAMBDA_TASK_ROOT")) != ""
	hasRuntimeAPI := strings.TrimSpace(os.Getenv("AWS_LAMBDA_RUNTIME_API")) != ""

	if fnName == "" && !hasTaskRoot && !hasRuntimeAPI {
		return nil, errors.New("aws-lambda: not running inside an aws lambda environment")
	}

	arn := r.functionARN
	if arn == "" {
		arn = strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_ARN"))
	}

	region := r.region
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_REGION"))
	}
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}

	accountID := r.accountID
	if accountID == "" {
		accountID = strings.TrimSpace(os.Getenv("AWS_ACCOUNT_ID"))
	}

	// If ARN is provided, extract region, account ID, and function name if still missing
	if arn != "" {
		arnRegion, arnAccount, arnFn := parseLambdaARN(arn)
		if region == "" && arnRegion != "" {
			region = arnRegion
		}
		if accountID == "" && arnAccount != "" {
			accountID = arnAccount
		}
		if fnName == "" && arnFn != "" {
			fnName = arnFn
		}
	}

	if fnName == "" {
		return nil, errors.New("aws-lambda: unable to determine lambda function name")
	}

	components := make(map[string]string)
	components["os"] = runtime.GOOS
	components["arch"] = runtime.GOARCH
	components["function_name"] = fnName

	if region != "" {
		components["region"] = region
	}
	if accountID != "" {
		components["account_id"] = accountID
	}
	if arn != "" {
		components["function_arn"] = arn
	}

	mem := r.memorySizeMB
	if mem == "" {
		mem = strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"))
	}
	if mem != "" {
		components["memory_size_mb"] = mem
	}

	rt := r.runtimeEnv
	if rt == "" {
		rt = strings.TrimSpace(os.Getenv("AWS_EXECUTION_ENV"))
	}
	if rt != "" {
		components["runtime"] = rt
	}

	digest, short := computeCanonicalDigest(PlatformAWSLambda, components)

	return &MachineFingerprint{
		Primary:         fmt.Sprintf("fp:lambda:%s", short),
		Platform:        PlatformAWSLambda,
		CanonicalDigest: digest,
		ShortDigest:     short,
		Components:      components,
		ResolvedAt:      time.Now().UTC(),
	}, nil
}

// parseLambdaARN parses standard AWS Lambda ARNs:
// arn:aws:lambda:<region>:<account-id>:function:<function-name>[:<version-or-alias>]
func parseLambdaARN(arnStr string) (region, accountID, fnName string) {
	parts := strings.Split(arnStr, ":")
	if len(parts) >= 7 && parts[0] == "arn" && parts[2] == "lambda" && parts[5] == "function" {
		region = parts[3]
		accountID = parts[4]
		fnName = parts[6]
	}
	return region, accountID, fnName
}

// ResolveAWSLambdaFingerprint resolves the machine identity for an AWS Lambda function.
func ResolveAWSLambdaFingerprint() (*MachineFingerprint, error) {
	return NewAWSLambdaResolver().Resolve(context.Background())
}

// ResolveAWSLambdaFingerprintWithContext resolves the machine identity for an AWS Lambda function with context.
func ResolveAWSLambdaFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewAWSLambdaResolver().Resolve(ctx)
}

// --- Kubernetes Resolver ---

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

// WithKubernetesClusterID sets an explicit cluster ID to bypass API server discovery.
func WithKubernetesClusterID(id string) KubernetesOption {
	return func(r *KubernetesResolver) {
		r.clusterID = strings.TrimSpace(id)
	}
}

// WithAllowInsecureNamespaceClusterID permits falling back to 'ns:<namespace>' when cluster identity
// cannot be uniquely established (e.g., in mock test environments where neither the Kubernetes API
// nor ca.crt is available). This option must NOT be used in production environments due to the risk
// of worldwide fingerprint collisions across clusters sharing the same namespace.
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
	clusterID                       string
	allowInsecureNamespaceClusterID bool
}

// NewKubernetesResolver constructs a new KubernetesResolver with optional configuration.
func NewKubernetesResolver(opts ...KubernetesOption) *KubernetesResolver {
	r := &KubernetesResolver{
		serviceAccountDir: defaultK8sServiceAcctDir,
		apiBaseURL:        defaultK8sAPIBaseURL,
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

	digest, short := computeCanonicalDigest(PlatformKubernetes, components)

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
		tlsConfig := &tls.Config{}
		if caData, err := os.ReadFile(caPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caData) {
				tlsConfig.RootCAs = pool
			}
		}
		client = &http.Client{
			Timeout: defaultK8sTimeout,
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

// --- Composite Resolver ---

// CompositeResolver evaluates multiple resolvers in sequence until one successfully resolves.
type CompositeResolver struct {
	resolvers []FingerprintResolver
}

// NewCompositeResolver creates a CompositeResolver with the specified list of resolvers.
func NewCompositeResolver(resolvers ...FingerprintResolver) *CompositeResolver {
	return &CompositeResolver{
		resolvers: resolvers,
	}
}

// NewDefaultCompositeResolver creates a CompositeResolver with default priority:
// 1. AWS Lambda (if running in Lambda, instant env check, avoids IMDS timeout)
// 2. Kubernetes (if in-cluster)
// 3. AWS EC2 (if running on EC2)
// 4. Host hardware (OS / Bare metal / VM fallback)
func NewDefaultCompositeResolver() *CompositeResolver {
	return NewCompositeResolver(
		NewAWSLambdaResolver(),
		NewKubernetesResolver(),
		NewAWSEC2Resolver(),
		NewHostResolver(),
	)
}

// Name returns the descriptive name of the resolver.
func (c *CompositeResolver) Name() string {
	return "composite"
}

// Platform returns PlatformGeneric as the aggregate platform.
func (c *CompositeResolver) Platform() Platform {
	return PlatformGeneric
}

// Resolve tries each resolver in sequence, returning the first successful MachineFingerprint.
func (c *CompositeResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	if len(c.resolvers) == 0 {
		return nil, errors.New("composite: no resolvers configured")
	}

	var errs []string
	for _, r := range c.resolvers {
		fp, err := r.Resolve(ctx)
		if err == nil && fp != nil {
			return fp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.Name(), err))
		}
	}

	return nil, fmt.Errorf("composite: all resolvers failed (%s)", strings.Join(errs, "; "))
}

// ResolveDefaultFingerprint automatically detects and resolves the machine identity using the default hierarchy.
func ResolveDefaultFingerprint() (*MachineFingerprint, error) {
	return NewDefaultCompositeResolver().Resolve(context.Background())
}

// ResolveDefaultFingerprintWithContext automatically detects and resolves machine identity with context.
func ResolveDefaultFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewDefaultCompositeResolver().Resolve(ctx)
}
