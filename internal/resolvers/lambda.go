package resolvers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

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

// NewAWSLambdaResolver creates a new AWSLambdaResolver with optional configuration overrides.
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

func (r *AWSLambdaResolver) hasExplicitOptions() bool {
	return r.functionName != "" || r.region != "" || r.accountID != "" ||
		r.functionARN != "" || r.memorySizeMB != "" || r.runtimeEnv != ""
}

func isLambdaRuntime() bool {
	fnName := strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_NAME"))
	arn := strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_ARN"))
	if fnName == "" && arn == "" {
		return false
	}

	taskRoot := strings.TrimSpace(os.Getenv("LAMBDA_TASK_ROOT"))
	runtimeAPI := strings.TrimSpace(os.Getenv("AWS_LAMBDA_RUNTIME_API"))

	if taskRoot == "" && runtimeAPI == "" {
		return false
	}

	if runtime.GOOS == "linux" && taskRoot != "" && runtimeAPI == "" {
		if _, err := os.Stat(taskRoot); err != nil {
			if _, err2 := os.Stat("/var/task"); err2 != nil {
				if _, err3 := os.Stat("/var/runtime"); err3 != nil {
					return false
				}
			}
		}
	}

	return true
}

// Resolve reads AWS Lambda environment variables and returns a deterministic MachineFingerprint.
func (r *AWSLambdaResolver) Resolve(ctx context.Context) (*MachineFingerprint, error) {
	if !r.hasExplicitOptions() && !isLambdaRuntime() {
		return nil, errors.New("aws-lambda: not running inside an aws lambda environment")
	}

	fnName := r.functionName
	if fnName == "" {
		fnName = strings.TrimSpace(os.Getenv("AWS_LAMBDA_FUNCTION_NAME"))
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

	digest, short := ComputeCanonicalDigest(PlatformAWSLambda, components)

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

// ResolveAWSLambdaFingerprint resolves the machine identity for an AWS Lambda runtime.
func ResolveAWSLambdaFingerprint() (*MachineFingerprint, error) {
	return NewAWSLambdaResolver().Resolve(context.Background())
}

// ResolveAWSLambdaFingerprintWithContext resolves the machine identity for an AWS Lambda runtime with context.
func ResolveAWSLambdaFingerprintWithContext(ctx context.Context) (*MachineFingerprint, error) {
	return NewAWSLambdaResolver().Resolve(ctx)
}
