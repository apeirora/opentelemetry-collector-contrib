// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"fmt"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
)

func TestIsDiscardableProcessingError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "retryable",
			err:  errors.New("temporary exporter failure"),
			want: false,
		},
		{
			name: "permanent",
			err:  consumererror.NewPermanent(errors.New("verification failed")),
			want: true,
		},
		{
			name: "rejected verify legacy",
			err:  fmt.Errorf("%s: %w", rejectedVerifyFailed, errors.New("hmac mismatch")),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isDiscardableProcessingError(tt.err); got != tt.want {
				t.Fatalf("isDiscardableProcessingError() = %v, want %v", got, tt.want)
			}
		})
	}
}
