package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const (
	defaultEC2BaseURL = "http://169.254.169.254"
	// defaultEC2Timeout bounds each IMDS attempt. IMDS normally answers in
	// milliseconds but can stall under load; a too-short timeout makes the
	// resolver fail intermittently, which flips the machine fingerprint.
	defaultEC2Timeout  = 1 * time.Second
	defaultEC2Attempts = 3
)

// errNotEC2 is returned by a detection-gated resolver when the process does not run on EC2.
var errNotEC2 = errors.New("aws-ec2: not running on an EC2 instance")

// AWSEC2Option configures an AWSEC2Resolver.
type AWSEC2Option func(*AWSEC2Resolver)

// WithAWSEC2BaseURL overrides the default IMDSv2 base URL (useful for testing).
func WithAWSEC2BaseURL(rawURL string) AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		r.baseURL = strings.TrimRight(rawURL, "/")
		r.customBaseURL = true
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

// WithAWSEC2Attempts sets how many times IMDSv2 is queried before giving up
// (minimum 1). Transient failures such as timeouts or HTTP 5xx are retried.
func WithAWSEC2Attempts(n int) AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		if n < 1 {
			n = 1
		}
		r.attempts = n
		r.attemptsSet = true
	}
}

// withEC2DetectionGate makes the resolver fail fast unless IsLikelyAWSEC2
// reports true. The default composite resolver uses it so non-EC2 machines do
// not pay for IMDS retries on every licence check.
func withEC2DetectionGate() AWSEC2Option {
	return func(r *AWSEC2Resolver) {
		r.requireDetection = true
	}
}

// AWSEC2Resolver inspects AWS EC2 IMDSv2 metadata to extract instance identity.
type AWSEC2Resolver struct {
	baseURL          string
	timeout          time.Duration
	attempts         int
	attemptsSet      bool
	customBaseURL    bool
	httpClient       *http.Client
	requireDetection bool
}

// NewAWSEC2Resolver creates a new AWSEC2Resolver with optional configuration.
func NewAWSEC2Resolver(opts ...AWSEC2Option) *AWSEC2Resolver {
	r := &AWSEC2Resolver{
		baseURL:  strings.TrimRight(ec2ProbeBaseURL, "/"),
		timeout:  defaultEC2Timeout,
		attempts: defaultEC2Attempts,
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
// Transient failures are retried up to the configured number of attempts, within
// the deadline of ctx. The returned fingerprint carries the host-hardware
// fingerprint in Alternates so licences bound to either identity keep matching.
func (r *AWSEC2Resolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	if r.requireDetection && !IsLikelyAWSEC2() {
		return nil, errNotEC2
	}

	attempts := r.attempts
	// Off EC2 the default IMDS address usually black-holes, so retrying would only
	// add latency. Retry by default only where EC2 was detected (or when the caller
	// configured an endpoint or attempt count explicitly).
	if !r.attemptsSet && !r.customBaseURL && !IsLikelyAWSEC2() {
		attempts = 1
	}
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
			case <-time.After(time.Duration(i) * retryBackoff):
			}
		}
		fp, err := r.resolveOnce(ctx)
		if err == nil {
			if host, herr := NewHostResolver().Resolve(ctx); herr == nil && host != nil {
				fp.Alternates = []MachineFingerprint{*host}
			}
			return fp, nil
		}
		lastErr = err
		if !isRetryableHTTPError(err) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (r *AWSEC2Resolver) resolveOnce(ctx context.Context) (*MachineFingerprint, error) {
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
	defer func() { _ = tokenResp.Body.Close() }()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{code: tokenResp.StatusCode, msg: fmt.Sprintf("aws-ec2: IMDSv2 token endpoint returned HTTP %d", tokenResp.StatusCode)}
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
	defer func() { _ = docResp.Body.Close() }()

	if docResp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{code: docResp.StatusCode, msg: fmt.Sprintf("aws-ec2: instance identity endpoint returned HTTP %d", docResp.StatusCode)}
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

	digest, short := ComputeCanonicalDigest(PlatformAWSEC2, components)

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
