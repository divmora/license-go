package resolvers

import (
	"errors"
	"net/http"
	"time"
)

// retryBackoff is the base delay between attempts of a metadata/API lookup.
const retryBackoff = 100 * time.Millisecond

// httpStatusError carries a non-OK HTTP status from a metadata or API endpoint.
// Only 429 and 5xx are treated as transient.
type httpStatusError struct {
	msg  string
	code int
}

func (e *httpStatusError) Error() string { return e.msg }

// isRetryableHTTPError reports whether err is worth retrying: network errors,
// timeouts and truncated bodies are; definitive answers (401, 403, 404, ...) are not.
func isRetryableHTTPError(err error) bool {
	var pe *permanentError
	if errors.As(err, &pe) {
		return false
	}
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.code >= 500 || se.code == http.StatusTooManyRequests
	}
	return true
}

// permanentError marks a failure that retrying cannot fix (e.g. a missing local file).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }
