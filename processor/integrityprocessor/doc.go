// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate mdatagen metadata.yaml

// Package integrityprocessor implements a processor that adds HMAC signatures
// to log records for tampering detection and data integrity verification.
// It supports both OpenBao Transit for centralized key management and local
// secret storage for simpler deployments.
package integrityprocessor
