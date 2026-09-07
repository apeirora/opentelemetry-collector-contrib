// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor/internal/metadatatest"
)

func TestVerifyTelemetryPassedAndFailed(t *testing.T) {
	t.Parallel()
	tt := componenttest.NewTelemetry()
	t.Cleanup(func() {
		require.NoError(t, tt.Shutdown(context.Background()))
	})

	settings := metadatatest.NewSettings(tt)
	sink := &consumertest.LogsSink{}
	p, err := newProcessor(&Config{
		Mode:                ModeSync,
		HmacKeyFile:         filepath.Join("testdata", "dev_hmac_key.txt"),
		FailureMode:         FailureModeMark,
		VerificationProfile: "default",
	}, sink, settings)
	require.NoError(t, err)

	passed := buildSignedHMACRecord(t, "rec-telemetry-pass")
	require.NoError(t, p.ConsumeLogs(context.Background(), passed))

	failed := buildSignedHMACRecord(t, "rec-telemetry-fail")
	failed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr(auditAttrIntegrityVal, "00")
	require.NoError(t, p.ConsumeLogs(context.Background(), failed))

	metadatatest.AssertEqualProcessorCertificatelogverifyRecords(t, tt, []metricdata.DataPoint[int64]{
		{
			Attributes: attribute.NewSet(
				attribute.String("outcome", "passed"),
				attribute.String("reason", "ok"),
			),
			Value: 1,
		},
		{
			Attributes: attribute.NewSet(
				attribute.String("outcome", "failed"),
				attribute.String("reason", "integrity_mismatch"),
			),
			Value: 1,
		},
	}, metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreExemplars())

	metadatatest.AssertEqualProcessorCertificatelogverifyDeadLetter(t, tt, []metricdata.DataPoint[int64]{
		{
			Attributes: attribute.NewSet(
				attribute.String("result", "skipped"),
				attribute.String("reason", "integrity_mismatch"),
			),
			Value: 1,
		},
	}, metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreExemplars())
}
