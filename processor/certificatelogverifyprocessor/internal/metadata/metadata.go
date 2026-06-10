// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"go.opentelemetry.io/collector/component"
)

var (
	Type = component.MustNewType("certificatelogverify")
)

const (
	LogsStability    = component.StabilityLevelAlpha
	TracesStability  = component.StabilityLevelUndefined
	MetricsStability = component.StabilityLevelUndefined
)
