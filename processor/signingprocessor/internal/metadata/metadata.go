// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package metadata contains the component.Type and stability metadata for the signing processor.
package metadata

import (
	"go.opentelemetry.io/collector/component"
)

var (
	Type = component.MustNewType("signing")
)

const (
	LogsStability    = component.StabilityLevelAlpha
	TracesStability  = component.StabilityLevelUndefined
	MetricsStability = component.StabilityLevelUndefined
)
