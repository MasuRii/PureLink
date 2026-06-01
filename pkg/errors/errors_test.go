package errors

import (
	stderrors "errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	sentinels := []error{ErrInvalidEndpoint, ErrInvalidConfig, ErrFileNotFound, ErrDirectoryNotFound, ErrV2rayNNotDetected, ErrV2rayNDBNotFound, ErrProviderTimeout, ErrProviderRateLimited, ErrAllProvidersFailed, ErrNetworkUnreachable, ErrBatchEmpty, ErrWorkerPanic}
	for _, s := range sentinels {
		if !stderrors.Is(fmt.Errorf("wrap: %w", s), s) {
			t.Fatalf("errors.Is failed for %v", s)
		}
	}
}
func TestValidationErrorAs(t *testing.T) {
	err := fmt.Errorf("wrap: %w", &ValidationError{Field: "workers", Message: "must be between 1 and 256"})
	var ve *ValidationError
	if !stderrors.As(err, &ve) || ve.Field != "workers" {
		t.Fatalf("errors.As failed: %v", err)
	}
}
