// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"net/http"

	"go.opentelemetry.io/collector/consumer/consumererror"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/errorutil"
)

var errCircuitOpen = errors.New("circuit breaker is open, temporarily unavailable")

type auditHTTPError struct {
	status int
	err    error
}

func (e *auditHTTPError) Error() string {
	return e.err.Error()
}

func newUnavailableError(msg string) error {
	return &auditHTTPError{status: http.StatusServiceUnavailable, err: errors.New(msg)}
}

func writeAuditHTTPError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	http.Error(w, err.Error(), auditHTTPStatus(err))
}

func auditHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var ahe *auditHTTPError
	if errors.As(err, &ahe) {
		return ahe.status
	}
	return errorutil.GetHTTPStatusCodeFromError(err)
}

func mapPipelineError(err error) error {
	if err == nil {
		return nil
	}
	if consumererror.IsPermanent(err) {
		return consumererror.NewPermanent(err)
	}
	return err
}
