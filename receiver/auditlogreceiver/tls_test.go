// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver/internal/metadata"
)

type mockStorageExtension struct {
	client storage.Client
}

func (m *mockStorageExtension) Start(context.Context, component.Host) error { return nil }

func (m *mockStorageExtension) Shutdown(context.Context) error { return nil }

func (m *mockStorageExtension) GetClient(context.Context, component.Kind, component.ID, string) (storage.Client, error) {
	return m.client, nil
}

type testHost struct {
	extensions map[component.ID]component.Component
}

func (h *testHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

func (h *testHost) GetFactory(_ component.Kind, _ component.Type) component.Factory {
	return nil
}

func availableLocalAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return addr
}

func tlsTestConfig(addr string, mtls bool) *Config {
	tlsCfg := configtls.ServerConfig{
		Config: configtls.Config{
			CertFile: "./testdata/tls/server.crt",
			KeyFile:  "./testdata/tls/server.key",
		},
	}
	if mtls {
		tlsCfg.ClientCAFile = "./testdata/tls/ca.crt"
	}

	sc := confighttp.NewDefaultServerConfig()
	sc.Endpoint = addr
	sc.TLS = configoptional.Some(tlsCfg)

	return &Config{
		ServerConfig: sc,
		StorageID:    component.NewIDWithName(component.MustNewType("file_storage"), ""),
		ResponseMode: ResponseModeSync,
	}
}

func tlsClientConfig(mtls bool) configtls.ClientConfig {
	cfg := configtls.ClientConfig{
		Config: configtls.Config{
			CAFile: "./testdata/tls/ca.crt",
		},
		ServerName: "localhost",
	}
	if mtls {
		cfg.CertFile = "./testdata/tls/client.crt"
		cfg.KeyFile = "./testdata/tls/client.key"
	}
	return cfg
}

func startTLSReceiver(t *testing.T, cfg *Config, consumer *mockConsumer) *auditLogReceiver {
	t.Helper()
	settings := receivertest.NewNopSettings(metadata.Type)
	r, err := NewReceiver(cfg, settings, consumer)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}

	storageID := cfg.StorageID
	host := &testHost{
		extensions: map[component.ID]component.Component{
			storageID: &mockStorageExtension{client: newMapStorageClient()},
		},
	}

	if err := r.Start(t.Context(), host); err != nil {
		t.Fatalf("Start: %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.Shutdown(shutdownCtx); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	})

	time.Sleep(100 * time.Millisecond)
	return r
}

func postAuditHTTPS(t *testing.T, url string, tlsCfg *tls.Config, body []byte) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return client.Do(req)
}

func TestReceiverTLS(t *testing.T) {
	t.Parallel()

	addr := availableLocalAddress(t)
	consumer := &mockConsumer{}
	startTLSReceiver(t, tlsTestConfig(addr, false), consumer)

	clientTLS, err := tlsClientConfig(false).LoadTLSConfig(t.Context())
	if err != nil {
		t.Fatalf("load client tls: %v", err)
	}

	url := "https://" + addr + defaultPath
	resp, err := postAuditHTTPS(t, url, clientTLS, testOTLPRequest(t))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(consumer.logs) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(consumer.logs))
	}
}

func TestReceiverMTLSRejectsClientWithoutCert(t *testing.T) {
	t.Parallel()

	addr := availableLocalAddress(t)
	consumer := &mockConsumer{}
	startTLSReceiver(t, tlsTestConfig(addr, true), consumer)

	clientTLS, err := tlsClientConfig(false).LoadTLSConfig(t.Context())
	if err != nil {
		t.Fatalf("load client tls: %v", err)
	}

	url := "https://" + addr + defaultPath
	_, err = postAuditHTTPS(t, url, clientTLS, testOTLPRequest(t))
	if err == nil {
		t.Fatal("expected TLS handshake failure without client certificate")
	}
	if len(consumer.logs) != 0 {
		t.Fatalf("expected no consumed logs, got %d", len(consumer.logs))
	}
}

func TestReceiverMTLSAcceptsClientWithCert(t *testing.T) {
	t.Parallel()

	addr := availableLocalAddress(t)
	consumer := &mockConsumer{}
	startTLSReceiver(t, tlsTestConfig(addr, true), consumer)

	clientTLS, err := tlsClientConfig(true).LoadTLSConfig(t.Context())
	if err != nil {
		t.Fatalf("load client tls: %v", err)
	}

	url := "https://" + addr + defaultPath
	resp, err := postAuditHTTPS(t, url, clientTLS, testOTLPRequest(t))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(consumer.logs) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(consumer.logs))
	}
}

var (
	_ extension.Extension = (*mockStorageExtension)(nil)
	_ storage.Extension   = (*mockStorageExtension)(nil)
)
