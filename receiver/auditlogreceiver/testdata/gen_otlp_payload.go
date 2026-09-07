//go:build ignore

package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	hmacKey   = "testapp-dev-hmac-key-change-in-production"
	certPath  = "../../../processor/certificatelogverifyprocessor/k8s/certificates/cert.pem"
	keyPath   = "../../../processor/certificatelogverifyprocessor/k8s/certificates/key.pem"
	outDir    = "."
)

type otlpJSON struct {
	ResourceLogs []resourceLog `json:"resourceLogs"`
}

type resourceLog struct {
	ScopeLogs []scopeLog `json:"scopeLogs"`
}

type scopeLog struct {
	LogRecords []logRecord `json:"logRecords"`
}

type logRecord struct {
	TimeUnixNano   string      `json:"timeUnixNano"`
	Body           value       `json:"body"`
	Attributes     []kv        `json:"attributes"`
}

type value struct {
	StringValue string `json:"stringValue"`
}

type kv struct {
	Key   string `json:"key"`
	Value value  `json:"value"`
}

func main() {
	certPEM, err := os.ReadFile(filepath.Join(outDir, certPath))
	if err != nil {
		fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(outDir, keyPath))
	if err != nil {
		fatal(err)
	}
	priv, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		fatal(err)
	}
	_ = certPEM

	now := time.Now().UTC()
	ts := fmt.Sprintf("%d", now.UnixNano())

	validBody := `{"event":"curl.test.valid","n":0,"id":"rec-curl-valid"}`
	invalidBody := `{"event":"curl.test.invalid","n":1,"id":"rec-curl-invalid"}`

	valid := buildRequest(ts, validBody, signBody(validBody, priv, true))
	invalid := buildRequest(ts, invalidBody, signBody(invalidBody, priv, false))

	writeJSON(filepath.Join(outDir, "otlp-valid.json"), valid)
	writeJSON(filepath.Join(outDir, "otlp-invalid.json"), invalid)
	fmt.Println("wrote otlp-valid.json and otlp-invalid.json")
}

func buildRequest(ts, body string, attrs []kv) otlpJSON {
	rec := logRecord{
		TimeUnixNano: ts,
		Body:         value{StringValue: body},
		Attributes:   attrs,
	}
	return otlpJSON{
		ResourceLogs: []resourceLog{
			{ScopeLogs: []scopeLog{{LogRecords: []logRecord{rec}}}},
		},
	}
}

func signBody(body string, priv *rsa.PrivateKey, valid bool) []kv {
	bodyBytes := []byte(body)
	sum := sha256.Sum256(bodyBytes)
	hashHex := hex.EncodeToString(sum[:])

	mac := hmac.New(sha256.New, []byte(hmacKey))
	_, _ = mac.Write(bodyBytes)
	hmacHex := hex.EncodeToString(mac.Sum(nil))
	if !valid {
		hmacHex = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		fatal(err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	recordID := "rec-curl-invalid"
	if valid {
		recordID = "rec-curl-valid"
	}
	return []kv{
		{Key: "audit.record_id", Value: value{StringValue: recordID}},
		{Key: "sign_content", Value: value{StringValue: "body"}},
		{Key: "audit.hash", Value: value{StringValue: hashHex}},
		{Key: "audit.hmac", Value: value{StringValue: hmacHex}},
		{Key: "audit.signature", Value: value{StringValue: sigB64}},
	}
}

func parseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
