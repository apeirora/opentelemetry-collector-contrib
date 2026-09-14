package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certDir := filepath.Join(".", "certificates")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating certificates directory: %v\n", err)
		os.Exit(1)
	}

	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")

	fmt.Println("========================================")
	fmt.Println("Generate RSA Certificate for Processor")
	fmt.Println("========================================")
	fmt.Println()

	fmt.Println("Step 1: Generating RSA private key (2048 bits)...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
		os.Exit(1)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Private key generated: %s\n", keyPath)

	fmt.Println()
	fmt.Println("Step 2: Generating self-signed certificate...")

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "otel-certificatelogverify-processor",
			Organization: []string{"OpenTelemetry"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating certificate: %v\n", err)
		os.Exit(1)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating certificate file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding certificate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Certificate generated: %s\n", certPath)

	fmt.Println()
	fmt.Println("Step 3: Verifying certificate...")
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("SUCCESS! Certificate files created")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("Certificate: %s\n", certPath)
	fmt.Printf("Private Key: %s\n", keyPath)
	fmt.Println()
	fmt.Println("Certificate Details:")
	fmt.Printf("  Subject: %s\n", cert.Subject.String())
	fmt.Printf("  Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("  Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Println()
	fmt.Println("To create Kubernetes secret, run:")
	fmt.Printf("  kubectl create secret generic otelcol-test-certs --from-file=cert.pem=%s --from-file=key.pem=%s -n otel-demo\n", certPath, keyPath)
	fmt.Println()
}
