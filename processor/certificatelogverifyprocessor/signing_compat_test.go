// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

func TestVerifyIntegrityRS256WithCertificateRef(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signing-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	now := time.Date(2026, 5, 18, 9, 35, 39, 611093600, time.UTC)
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
	lr.SetEventName("user.login")
	lr.SetSeverityNumber(plog.SeverityNumberInfo)
	lr.SetSeverityText("INFO")
	lr.Body().SetStr(`{"event":"user.login"}`)
	lr.Attributes().PutStr(auditAttrRecordID, "rec-rs256")
	lr.Attributes().PutStr(auditAttrActorID, "alice@example.com")

	canonical, err := serializeLogRecord(lr)
	require.NoError(t, err)

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(canonical)
	require.NoError(t, err)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hasher.Sum(nil))
	require.NoError(t, err)
	lr.Attributes().PutStr(auditAttrIntegrityVal, base64.StdEncoding.EncodeToString(sig))

	sum := sha256.Sum256(cert.Raw)
	fingerprint := "sha256:" + hex.EncodeToString(sum[:])

	resource := pcommon.NewResource()
	resource.Attributes().PutStr(auditIntegrityAlgorithmKey, algoRS256)
	resource.Attributes().PutStr(auditIntegrityCertificateKey, fingerprint)

	p := &verifyProcessor{
		logger: zap.NewNop(),
		cert:   cert,
	}
	reason, err := p.verifyAuditLogRecord(resource, lr)
	require.NoError(t, err, "reason=%s", reason)
	assert.Equal(t, reasonOK, reason)

	resource.Attributes().PutStr(auditIntegrityCertificateKey, "sha256:deadbeef")
	reason, err = p.verifyAuditLogRecord(resource, lr)
	require.Error(t, err)
	assert.Equal(t, "certificate_ref_mismatch", reason)
}
