package errors

import (
	stderrors "errors"
	"fmt"
)

var (
	ErrInvalidEndpoint     = stderrors.New("invalid endpoint format")
	ErrInvalidConfig       = stderrors.New("invalid configuration")
	ErrFileNotFound        = stderrors.New("file not found")
	ErrDirectoryNotFound   = stderrors.New("directory not found")
	ErrV2rayNNotDetected   = stderrors.New("v2rayN installation not detected")
	ErrV2rayNDBNotFound    = stderrors.New("v2rayN database not found")
	ErrProviderTimeout     = stderrors.New("provider request timed out")
	ErrProviderRateLimited = stderrors.New("provider rate limited")
	ErrAllProvidersFailed  = stderrors.New("all providers failed")
	ErrNetworkUnreachable  = stderrors.New("network unreachable")
	ErrBatchEmpty          = stderrors.New("batch input is empty")
	ErrWorkerPanic         = stderrors.New("worker panic recovered")
)

type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field %q: %s", e.Field, e.Message)
}
