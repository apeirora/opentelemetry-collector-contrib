// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor"

import "go.uber.org/zap"

func componentLogger(base *zap.Logger) *zap.Logger {
	return base.WithOptions(zap.AddStacktrace(zap.PanicLevel))
}

func errString(err error) zap.Field {
	return zap.String("error", err.Error())
}
