// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package metadata contains the component.Type and stability metadata for the certificatehash processor.
package metadata

import (
	"go.opentelemetry.io/collector/component"
)

var (
	Type = component.MustNewType("certificatehash")
)

const (
	LogsStability    = component.StabilityLevelAlpha
	TracesStability  = component.StabilityLevelUndefined
	MetricsStability = component.StabilityLevelUndefined
)
