package license

import (
	"context"
	"net/http"
	"time"

	"github.com/divmora/license-go/internal/resolvers"
)

// AWSEC2Option configures an AWSEC2Resolver.
type AWSEC2Option = resolvers.AWSEC2Option

// WithAWSEC2BaseURL overrides the default IMDSv2 base URL.
func WithAWSEC2BaseURL(rawURL string) AWSEC2Option {
	return resolvers.WithAWSEC2BaseURL(rawURL)
}

// WithAWSEC2Timeout sets the HTTP timeout for IMDSv2 queries.
func WithAWSEC2Timeout(d time.Duration) AWSEC2Option {
	return resolvers.WithAWSEC2Timeout(d)
}

// WithAWSEC2HTTPClient sets a custom http.Client for IMDSv2 queries.
func WithAWSEC2HTTPClient(client *http.Client) AWSEC2Option {
	return resolvers.WithAWSEC2HTTPClient(client)
}

// AWSEC2Resolver inspects AWS EC2 IMDSv2 metadata to extract instance identity.
type AWSEC2Resolver = resolvers.AWSEC2Resolver

// NewAWSEC2Resolver creates a new AWSEC2Resolver with optional configuration.
func NewAWSEC2Resolver(opts ...AWSEC2Option) *AWSEC2Resolver {
	return resolvers.NewAWSEC2Resolver(opts...)
}

// ResolveAWSEC2Fingerprint resolves the machine identity for an AWS EC2 instance.
func ResolveAWSEC2Fingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveAWSEC2Fingerprint()
}

// ResolveAWSEC2FingerprintWithContext resolves the machine identity for an AWS EC2 instance with context.
func ResolveAWSEC2FingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveAWSEC2FingerprintWithContext(ctx)
}

// AWSLambdaOption configures an AWSLambdaResolver.
type AWSLambdaOption = resolvers.AWSLambdaOption

// WithAWSLambdaFunctionName explicitly sets the Lambda function name.
func WithAWSLambdaFunctionName(name string) AWSLambdaOption {
	return resolvers.WithAWSLambdaFunctionName(name)
}

// WithAWSLambdaRegion explicitly sets the AWS region.
func WithAWSLambdaRegion(region string) AWSLambdaOption {
	return resolvers.WithAWSLambdaRegion(region)
}

// WithAWSLambdaAccountID explicitly sets the AWS account ID.
func WithAWSLambdaAccountID(accountID string) AWSLambdaOption {
	return resolvers.WithAWSLambdaAccountID(accountID)
}

// WithAWSLambdaFunctionARN explicitly sets the full Lambda function ARN.
func WithAWSLambdaFunctionARN(arn string) AWSLambdaOption {
	return resolvers.WithAWSLambdaFunctionARN(arn)
}

// WithAWSLambdaMemorySize explicitly sets the memory size in MB.
func WithAWSLambdaMemorySize(mb string) AWSLambdaOption {
	return resolvers.WithAWSLambdaMemorySize(mb)
}

// WithAWSLambdaRuntime explicitly sets the execution runtime.
func WithAWSLambdaRuntime(rt string) AWSLambdaOption {
	return resolvers.WithAWSLambdaRuntime(rt)
}

// AWSLambdaResolver inspects AWS Lambda environment variables to extract function identity.
type AWSLambdaResolver = resolvers.AWSLambdaResolver

// NewAWSLambdaResolver creates a new AWSLambdaResolver with optional configuration overrides.
func NewAWSLambdaResolver(opts ...AWSLambdaOption) *AWSLambdaResolver {
	return resolvers.NewAWSLambdaResolver(opts...)
}

// ResolveAWSLambdaFingerprint resolves the machine identity for an AWS Lambda runtime.
func ResolveAWSLambdaFingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveAWSLambdaFingerprint()
}

// ResolveAWSLambdaFingerprintWithContext resolves the machine identity for an AWS Lambda runtime with context.
func ResolveAWSLambdaFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveAWSLambdaFingerprintWithContext(ctx)
}

// KubernetesOption configures a KubernetesResolver.
type KubernetesOption = resolvers.KubernetesOption

// WithKubernetesServiceAccountDir sets the path to the service account mount directory.
func WithKubernetesServiceAccountDir(dir string) KubernetesOption {
	return resolvers.WithKubernetesServiceAccountDir(dir)
}

// WithKubernetesAPIBaseURL sets the base URL for the Kubernetes API.
func WithKubernetesAPIBaseURL(rawURL string) KubernetesOption {
	return resolvers.WithKubernetesAPIBaseURL(rawURL)
}

// WithKubernetesTimeout sets the HTTP timeout for Kubernetes API requests.
func WithKubernetesTimeout(d time.Duration) KubernetesOption {
	return resolvers.WithKubernetesTimeout(d)
}

// WithKubernetesHTTPClient sets a custom http.Client for Kubernetes queries.
func WithKubernetesHTTPClient(client *http.Client) KubernetesOption {
	return resolvers.WithKubernetesHTTPClient(client)
}

// WithKubernetesClusterID sets an explicit cluster ID to bypass API server discovery.
func WithKubernetesClusterID(id string) KubernetesOption {
	return resolvers.WithKubernetesClusterID(id)
}

// WithAllowInsecureNamespaceClusterID permits falling back to 'ns:<namespace>' when cluster identity
// cannot be uniquely established.
func WithAllowInsecureNamespaceClusterID(allow bool) KubernetesOption {
	return resolvers.WithAllowInsecureNamespaceClusterID(allow)
}

// KubernetesResolver inspects Kubernetes in-cluster secrets and API to extract cluster identity.
type KubernetesResolver = resolvers.KubernetesResolver

// NewKubernetesResolver creates a new KubernetesResolver with optional configuration.
func NewKubernetesResolver(opts ...KubernetesOption) *KubernetesResolver {
	return resolvers.NewKubernetesResolver(opts...)
}

// ResolveKubernetesFingerprint resolves the machine identity for a Kubernetes cluster container.
func ResolveKubernetesFingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveKubernetesFingerprint()
}

// ResolveKubernetesFingerprintWithContext resolves the machine identity for a Kubernetes cluster container with context.
func ResolveKubernetesFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveKubernetesFingerprintWithContext(ctx)
}

// GenericContainerResolver resolves machine identity for non-K8s containerized workloads.
type GenericContainerResolver = resolvers.GenericContainerResolver

// NewGenericContainerResolver creates a new GenericContainerResolver.
func NewGenericContainerResolver() *GenericContainerResolver {
	return resolvers.NewGenericContainerResolver()
}

// ResolveGenericContainerFingerprint resolves the machine identity for a generic container.
func ResolveGenericContainerFingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveGenericContainerFingerprint()
}

// ResolveGenericContainerFingerprintWithContext resolves the machine identity for a generic container with context.
func ResolveGenericContainerFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveGenericContainerFingerprintWithContext(ctx)
}

// AutoDetectResolver automatically probes the runtime environment and delegates to the appropriate resolver.
type AutoDetectResolver = resolvers.AutoDetectResolver

// NewAutoDetectResolver creates a new AutoDetectResolver.
func NewAutoDetectResolver() *AutoDetectResolver {
	return resolvers.NewAutoDetectResolver()
}

// DetectEnvironment inspects runtime markers to determine the current execution platform.
func DetectEnvironment() Platform {
	return resolvers.DetectEnvironment()
}

// AutoDetectFingerprint resolves the machine identity automatically based on detected environment.
func AutoDetectFingerprint() (*MachineFingerprint, error) {
	return resolvers.AutoDetectFingerprint()
}

// AutoDetectFingerprintWithContext resolves the machine identity automatically with context.
func AutoDetectFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.AutoDetectFingerprintWithContext(ctx)
}

// CompositeResolver evaluates multiple resolvers in sequence until one successfully resolves.
type CompositeResolver = resolvers.CompositeResolver

// NewCompositeResolver creates a CompositeResolver with the specified list of resolvers.
func NewCompositeResolver(r ...FingerprintResolver) *CompositeResolver {
	return resolvers.NewCompositeResolver(r...)
}

// NewDefaultCompositeResolver creates a CompositeResolver with default priority.
func NewDefaultCompositeResolver() *CompositeResolver {
	return resolvers.NewDefaultCompositeResolver()
}

// ResolveDefaultFingerprint automatically detects and resolves the machine identity using the default hierarchy.
func ResolveDefaultFingerprint() (*MachineFingerprint, error) {
	return resolvers.ResolveDefaultFingerprint()
}

// ResolveDefaultFingerprintWithContext automatically detects and resolves machine identity with context.
func ResolveDefaultFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return resolvers.ResolveDefaultFingerprintWithContext(ctx)
}
