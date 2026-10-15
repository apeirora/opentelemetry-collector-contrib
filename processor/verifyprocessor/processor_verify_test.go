// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package verifyprocessor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.uber.org/zap"
)

type staticProvider struct {
	cert    *x509.Certificate
	hmacKey []byte
}

func (s *staticProvider) GetCertificate() *x509.Certificate { return s.cert }
func (s *staticProvider) GetHMACKey() []byte                { return s.hmacKey }

func newTestRSA(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verify-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, cert, certPEM
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newVerifyProc(t *testing.T, cfg *Config, prov KeyMaterialProvider) *verifyProcessor {
	t.Helper()
	return &verifyProcessor{
		config:       cfg,
		logger:       zap.NewNop(),
		nextConsumer: consumertest.NewNop(),
		provider:     prov,
	}
}

func signRSA(t *testing.T, key *rsa.PrivateKey, payload []byte, hash crypto.Hash) string {
	t.Helper()
	h := hash.New()
	_, err := h.Write(payload)
	require.NoError(t, err)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

func makeLogs(body string, attrs map[string]string, algorithm, certRef, sig string) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	if algorithm != "" {
		rl.Resource().Attributes().PutStr(attrIntegrityAlgorithm, algorithm)
	}
	if certRef != "" {
		rl.Resource().Attributes().PutStr(attrIntegrityCertificate, certRef)
	}
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr(body)
	lr.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(1, 0)))
	for k, v := range attrs {
		lr.Attributes().PutStr(k, v)
	}
	if sig != "" {
		lr.Attributes().PutStr(attrIntegrityValue, sig)
	}
	return ld
}

func TestVerifyRS256HappyPath(t *testing.T) {
	key, cert, _ := newTestRSA(t)
	p := newVerifyProc(t, &Config{FailureMode: failureModeStrict, VerificationProfile: "default"}, &staticProvider{cert: cert})

	ld := makeLogs("hello", map[string]string{"k": "v"}, algorithmRS256, fingerprint(cert), "")
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	payload, err := p.serializeLogRecord(lr)
	require.NoError(t, err)
	lr.Attributes().PutStr(attrIntegrityValue, signRSA(t, key, payload, crypto.SHA256))

	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	status, ok := lr.Attributes().Get(attrVerificationStatus)
	require.True(t, ok)
	assert.Equal(t, statusVerified, status.Str())
}

func TestVerifyHMACHappyPathAndTamper(t *testing.T) {
	hmacKey := []byte("super-secret-hmac-key")
	p := newVerifyProc(t, &Config{FailureMode: failureModeDrop, VerificationProfile: "default"}, &staticProvider{hmacKey: hmacKey})

	ld := makeLogs("hmac-body", nil, algorithmHMACSHA256, "", "")
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	payload, err := p.serializeLogRecord(lr)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, hmacKey)
	_, err = mac.Write(payload)
	require.NoError(t, err)
	lr.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	status, ok := lr.Attributes().Get(attrVerificationStatus)
	require.True(t, ok)
	assert.Equal(t, statusVerified, status.Str())

	ld2 := makeLogs("hmac-body", nil, algorithmHMACSHA256, "", "")
	lr2 := ld2.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	payload2, err := p.serializeLogRecord(lr2)
	require.NoError(t, err)
	mac2 := hmac.New(sha256.New, hmacKey)
	_, err = mac2.Write(payload2)
	require.NoError(t, err)
	lr2.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(mac2.Sum(nil)))
	lr2.Attributes().PutStr(attrRecordID, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	lr2.Body().SetStr("tampered")

	sink := &consumertest.LogsSink{}
	p.nextConsumer = sink
	err = p.ConsumeLogs(context.Background(), ld2)
	require.Error(t, err)
	assert.True(t, consumererror.IsPermanent(err))
	assert.Contains(t, err.Error(), "verification failed for 1 log record(s)")
	assert.Contains(t, err.Error(), "id=a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	assert.NotContains(t, err.Error(), "tampered")
	assert.Equal(t, 0, ld2.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
	assert.Equal(t, 0, sink.LogRecordCount())
}

func TestDropForwardsGoodAndReportsBadIDs(t *testing.T) {
	hmacKey := []byte("super-secret-hmac-key")
	sink := &consumertest.LogsSink{}
	p := newVerifyProc(t, &Config{FailureMode: failureModeDrop, VerificationProfile: "default"}, &staticProvider{hmacKey: hmacKey})
	p.nextConsumer = sink

	ld := makeLogs("ok-body", nil, algorithmHMACSHA256, "", "")
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	okRec := records.At(0)
	payload, err := p.serializeLogRecord(okRec)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, hmacKey)
	_, err = mac.Write(payload)
	require.NoError(t, err)
	okRec.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	var traceID pcommon.TraceID
	copy(traceID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	badRec := records.AppendEmpty()
	badRec.SetTraceID(traceID)
	badRec.SetEventName("audit.bad")
	badRec.Body().SetStr("tampered")
	badRec.Attributes().PutStr(attrRecordID, "rec-bad-2")
	badRec.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString([]byte("not-the-mac")))

	err = p.ConsumeLogs(context.Background(), ld)
	require.Error(t, err)
	assert.True(t, consumererror.IsPermanent(err))
	assert.Contains(t, err.Error(), "verification failed for 1 log record(s)")
	assert.Contains(t, err.Error(), "id=rec-bad-2")
	assert.NotContains(t, err.Error(), "record[")
	assert.NotContains(t, err.Error(), traceID.String())
	assert.NotContains(t, err.Error(), "audit.bad")
	assert.NotContains(t, err.Error(), "tampered")
	assert.NotContains(t, err.Error(), "ok-body")
	assert.Equal(t, 1, records.Len())
	assert.Equal(t, 1, sink.LogRecordCount())
	assert.Equal(t, "ok-body", sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str())
}

func TestStrictRejectsWholeBatch(t *testing.T) {
	hmacKey := []byte("super-secret-hmac-key")
	sink := &consumertest.LogsSink{}
	p := newVerifyProc(t, &Config{FailureMode: failureModeStrict, VerificationProfile: "default"}, &staticProvider{hmacKey: hmacKey})
	p.nextConsumer = sink

	ld := makeLogs("ok-body", nil, algorithmHMACSHA256, "", "")
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	okRec := records.At(0)
	payload, err := p.serializeLogRecord(okRec)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, hmacKey)
	_, err = mac.Write(payload)
	require.NoError(t, err)
	okRec.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	badRec := records.AppendEmpty()
	badRec.Body().SetStr("tampered")
	badRec.Attributes().PutStr(attrRecordID, "rec-bad-3")
	badRec.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString([]byte("not-the-mac")))

	err = p.ConsumeLogs(context.Background(), ld)
	require.Error(t, err)
	assert.True(t, consumererror.IsPermanent(err))
	assert.Contains(t, err.Error(), "id=rec-bad-3")
	assert.Equal(t, 2, records.Len())
	assert.Equal(t, 0, sink.LogRecordCount())
}

func TestVerifyMarkFailureMode(t *testing.T) {
	hmacKey := []byte("mark-key")
	p := newVerifyProc(t, &Config{FailureMode: failureModeMark, VerificationProfile: "default"}, &staticProvider{hmacKey: hmacKey})

	ld := makeLogs("body", nil, algorithmHMACSHA256, "", "not-valid-base64!!!")
	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	status, ok := lr.Attributes().Get(attrVerificationStatus)
	require.True(t, ok)
	assert.Equal(t, statusFailed, status.Str())
	reason, ok := lr.Attributes().Get(attrVerificationReason)
	require.True(t, ok)
	assert.Equal(t, reasonInvalidSignature, reason.Str())
}

func TestVerifyCertificateMismatch(t *testing.T) {
	key, cert, _ := newTestRSA(t)
	_, otherCert, _ := newTestRSA(t)
	p := newVerifyProc(t, &Config{FailureMode: failureModeMark, VerificationProfile: "default"}, &staticProvider{cert: cert})

	ld := makeLogs("hello", nil, algorithmRS256, fingerprint(otherCert), "")
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	payload, err := p.serializeLogRecord(lr)
	require.NoError(t, err)
	lr.Attributes().PutStr(attrIntegrityValue, signRSA(t, key, payload, crypto.SHA256))

	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	reason, ok := lr.Attributes().Get(attrVerificationReason)
	require.True(t, ok)
	assert.Equal(t, reasonCertificateMismatch, reason.Str())
}

func TestVerifyKeyMaterialMismatchWrongKeyType(t *testing.T) {
	_, cert, _ := newTestRSA(t)
	p := newVerifyProc(t, &Config{FailureMode: failureModeMark, VerificationProfile: "default"}, &staticProvider{cert: cert})

	ld := makeLogs("hello", nil, algorithmES256, fingerprint(cert), "YWJjZA==")
	require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	reason, ok := lr.Attributes().Get(attrVerificationReason)
	require.True(t, ok)
	assert.Equal(t, reasonKeyMaterialMismatch, reason.Str())
	status, ok := lr.Attributes().Get(attrVerificationStatus)
	require.True(t, ok)
	assert.Equal(t, statusFailed, status.Str())
}

func TestVerifyES256AndEdDSA(t *testing.T) {
	t.Run("ES256", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "ec"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		p := newVerifyProc(t, &Config{FailureMode: failureModeStrict, VerificationProfile: "default"}, &staticProvider{cert: cert})
		ld := makeLogs("ec-body", nil, algorithmES256, fingerprint(cert), "")
		lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		payload, err := p.serializeLogRecord(lr)
		require.NoError(t, err)
		sum := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
		require.NoError(t, err)
		lr.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(sig))
		require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	})

	t.Run("EdDSA", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "ed"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		p := newVerifyProc(t, &Config{FailureMode: failureModeStrict, VerificationProfile: "default"}, &staticProvider{cert: cert})
		ld := makeLogs("ed-body", nil, algorithmEdDSA, fingerprint(cert), "")
		lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		payload, err := p.serializeLogRecord(lr)
		require.NoError(t, err)
		sig := ed25519.Sign(priv, payload)
		lr.Attributes().PutStr(attrIntegrityValue, base64.StdEncoding.EncodeToString(sig))
		require.NoError(t, p.ConsumeLogs(context.Background(), ld))
	})
}

func TestFileAndEnvProviders(t *testing.T) {
	_, cert, certPEM := newTestRSA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	hmacPath := filepath.Join(dir, "hmac.key")
	rawHMAC := []byte("provider-hmac-secret")
	require.NoError(t, os.WriteFile(hmacPath, []byte(base64.StdEncoding.EncodeToString(rawHMAC)), 0o600))

	t.Run("file certificate", func(t *testing.T) {
		prov, err := newFileKeyMaterialProvider(&FileKeyConfig{Certificate: certPath})
		require.NoError(t, err)
		require.NotNil(t, prov.GetCertificate())
		assert.Equal(t, cert.Raw, prov.GetCertificate().Raw)
	})

	t.Run("file hmac", func(t *testing.T) {
		prov, err := newFileKeyMaterialProvider(&FileKeyConfig{HMACKey: hmacPath})
		require.NoError(t, err)
		assert.Equal(t, rawHMAC, prov.GetHMACKey())
	})

	t.Run("env certificate", func(t *testing.T) {
		prov, err := newInlineKeyMaterialProvider(&EnvKeyConfig{Certificate: string(certPEM)})
		require.NoError(t, err)
		require.NotNil(t, prov.GetCertificate())
	})

	t.Run("env hmac", func(t *testing.T) {
		prov, err := newInlineKeyMaterialProvider(&EnvKeyConfig{HMACKey: base64.StdEncoding.EncodeToString(rawHMAC)})
		require.NoError(t, err)
		assert.Equal(t, rawHMAC, prov.GetHMACKey())
	})

	t.Run("file missing", func(t *testing.T) {
		_, err := newFileKeyMaterialProvider(&FileKeyConfig{Certificate: filepath.Join(dir, "missing.pem")})
		require.Error(t, err)
	})
}

func TestStubProvidersNotImplemented(t *testing.T) {
	_, err := newKeyMaterialProvider(context.Background(), &Config{
		KeySource: KeySourceConfig{Type: keySourceK8sSecret, K8sSecret: &K8sSecretConfig{Name: "n", SecretConfig: SecretConfig{HMACKey: "k"}}},
	}, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")

	_, err = newKeyMaterialProvider(context.Background(), &Config{
		KeySource: KeySourceConfig{Type: keySourceBao, Bao: &BaoKeyConfig{SecretPath: "p", SecretConfig: SecretConfig{HMACKey: "k"}}},
	}, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestFactoryCreateWithFileHMAC(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.KeySource = KeySourceConfig{
		Type: keySourceFile,
		File: &FileKeyConfig{HMACKey: "testdata/dev_hmac_key.txt"},
	}
	proc, err := factory.CreateLogs(context.Background(), processortest.NewNopSettings(typ), cfg, consumertest.NewNop())
	require.NoError(t, err)
	assert.True(t, proc.Capabilities().MutatesData)
}

func TestIntegrityAttrsExcludedFromPayload(t *testing.T) {
	p := newVerifyProc(t, &Config{FailureMode: failureModeStrict, VerificationProfile: "default"}, &staticProvider{hmacKey: []byte("x")})
	ld := makeLogs("body", map[string]string{
		"keep":                 "yes",
		attrIntegrityValue:     "sig",
		attrVerificationStatus: "stale",
	}, algorithmHMACSHA256, "", "sig")
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	payload, err := p.serializeLogRecord(lr)
	require.NoError(t, err)
	assert.NotContains(t, string(payload), "audit.integrity")
	assert.NotContains(t, string(payload), "audit.verification")
	assert.Contains(t, string(payload), "keep")
}

func TestValidateSecretMaterialExactlyOne(t *testing.T) {
	assert.ErrorIs(t, validateSecretMaterial(SecretConfig{}), errKeySourceNeedsMaterial)
	assert.ErrorIs(t, validateSecretMaterial(SecretConfig{Certificate: "c", HMACKey: "h"}), errKeySourceBothMaterials)
	assert.NoError(t, validateSecretMaterial(SecretConfig{Certificate: "c"}))
	assert.NoError(t, validateSecretMaterial(SecretConfig{HMACKey: "h"}))
}
