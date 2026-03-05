package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type LogRecord struct {
	Body           interface{}            `json:"body,omitempty"`
	Attributes     map[string]interface{} `json:"attributes,omitempty"`
	Timestamp      *int64                 `json:"timestamp,omitempty"`
	SeverityNumber *int                   `json:"severity_number,omitempty"`
	SeverityText   *string                `json:"severity_text,omitempty"`
	TraceID        *string                `json:"trace_id,omitempty"`
	SpanID         *string                `json:"span_id,omitempty"`
}

type LogData struct {
	ResourceLogs []struct {
		ScopeLogs []struct {
			LogRecords []LogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

func main() {
	var (
		logFile  = flag.String("log", "", "Path to log file (JSON format) or '-' for stdin")
		certFile = flag.String("cert", "", "Path to certificate file (cert.pem)")
		hashAlgo = flag.String("hash", "SHA256", "Hash algorithm (SHA256 or SHA512)")
		verbose  = flag.Bool("verbose", false, "Show detailed output")
	)
	flag.Parse()

	if *logFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -log flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *certFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -cert flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	var hashFunc func() crypto.Hash
	switch strings.ToUpper(*hashAlgo) {
	case "SHA256":
		hashFunc = func() crypto.Hash { return crypto.SHA256 }
	case "SHA512":
		hashFunc = func() crypto.Hash { return crypto.SHA512 }
	default:
		fmt.Fprintf(os.Stderr, "Error: hash algorithm must be SHA256 or SHA512\n")
		os.Exit(1)
	}

	var logReader io.Reader
	if *logFile == "-" {
		logReader = os.Stdin
	} else {
		file, err := os.Open(*logFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		logReader = file
	}

	logData, err := io.ReadAll(logReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading log data: %v\n", err)
		os.Exit(1)
	}

	var logRecords []LogRecord
	var rawLog map[string]interface{}

	if err := json.Unmarshal(logData, &rawLog); err == nil {
		if resourceLogs, ok := rawLog["resourceLogs"].([]interface{}); ok {
			for _, rl := range resourceLogs {
				if rlMap, ok := rl.(map[string]interface{}); ok {
					if scopeLogs, ok := rlMap["scopeLogs"].([]interface{}); ok {
						for _, sl := range scopeLogs {
							if slMap, ok := sl.(map[string]interface{}); ok {
								if lrs, ok := slMap["logRecords"].([]interface{}); ok {
									for _, lr := range lrs {
										var record LogRecord
										if lrBytes, err := json.Marshal(lr); err == nil {
											if err := json.Unmarshal(lrBytes, &record); err == nil {
												logRecords = append(logRecords, record)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		} else {
			var singleRecord LogRecord
			if err := json.Unmarshal(logData, &singleRecord); err == nil {
				logRecords = append(logRecords, singleRecord)
			} else {
				fmt.Fprintf(os.Stderr, "Error: Could not parse log data as OTLP format or single record\n")
				os.Exit(1)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error parsing log JSON: %v\n", err)
		os.Exit(1)
	}

	if len(logRecords) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No log records found\n")
		os.Exit(1)
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to decode PEM certificate\n")
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Certificate does not contain RSA public key\n")
		os.Exit(1)
	}

	allValid := true
	for i, record := range logRecords {
		if *verbose {
			fmt.Printf("\n=== Verifying Log Record %d ===\n", i+1)
		}

		hashValue, ok := record.Attributes["otel.log.hash"].(string)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: Log record %d missing otel.log.hash attribute\n", i+1)
			allValid = false
			continue
		}

		signatureValue, ok := record.Attributes["otel.log.signature"].(string)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: Log record %d missing otel.log.signature attribute\n", i+1)
			allValid = false
			continue
		}

		signContent, _ := record.Attributes["otel.log.sign_content"].(string)
		if signContent == "" {
			signContent = "body"
		}

		data := make(map[string]interface{})

		if signContent == "body" || signContent == "meta" || signContent == "attr" {
			if record.Body != nil {
				if bodyStr, ok := record.Body.(string); ok {
					data["body"] = bodyStr
				}
			}
		}

		if signContent == "meta" || signContent == "attr" {
			if record.Timestamp != nil && *record.Timestamp != 0 {
				data["timestamp"] = *record.Timestamp
			}

			if record.SeverityNumber != nil && *record.SeverityNumber != 0 {
				data["severity_number"] = *record.SeverityNumber
			}

			if record.SeverityText != nil && *record.SeverityText != "" {
				data["severity_text"] = *record.SeverityText
			}

			if record.TraceID != nil && *record.TraceID != "" {
				data["trace_id"] = *record.TraceID
			}

			if record.SpanID != nil && *record.SpanID != "" {
				data["span_id"] = *record.SpanID
			}
		}

		if signContent == "attr" {
			attrs := make(map[string]interface{})
			for k, v := range record.Attributes {
				if !strings.HasPrefix(k, "otel.log.") {
					attrs[k] = v
				}
			}
			data["attributes"] = attrs
		}

		sortedData := sortMapKeys(data)
		serialized, err := json.Marshal(sortedData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing log record %d: %v\n", i+1, err)
			allValid = false
			continue
		}

		if *verbose {
			fmt.Printf("Serialized log data: %s\n", string(serialized))
		}

		var computedHash []byte
		hashAlgo := hashFunc()
		switch hashAlgo {
		case crypto.SHA256:
			h := sha256.Sum256(serialized)
			computedHash = h[:]
		case crypto.SHA512:
			h := sha512.Sum512(serialized)
			computedHash = h[:]
		}

		computedHashBase64 := base64.StdEncoding.EncodeToString(computedHash)

		hashMatch := computedHashBase64 == hashValue
		if *verbose {
			fmt.Printf("Computed hash: %s\n", computedHashBase64)
			fmt.Printf("Provided hash: %s\n", hashValue)
			fmt.Printf("Hash match: %v\n", hashMatch)
		}

		if !hashMatch {
			fmt.Printf("❌ Log record %d: Hash mismatch!\n", i+1)
			allValid = false
			continue
		}

		signatureBytes, err := base64.StdEncoding.DecodeString(signatureValue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding signature for record %d: %v\n", i+1, err)
			allValid = false
			continue
		}

		err = rsa.VerifyPKCS1v15(publicKey, hashAlgo, computedHash, signatureBytes)
		if err != nil {
			fmt.Printf("❌ Log record %d: Signature verification failed: %v\n", i+1, err)
			allValid = false
			continue
		}

		fmt.Printf("✅ Log record %d: Hash and signature verified successfully\n", i+1)
	}

	if allValid {
		fmt.Printf("\n✅ All log records verified successfully!\n")
		os.Exit(0)
	} else {
		fmt.Printf("\n❌ Some log records failed verification\n")
		os.Exit(1)
	}
}

func sortMapKeys(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		sorted := make(map[string]interface{})
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sorted[k] = sortMapKeys(val[k])
		}
		return sorted
	case []interface{}:
		sorted := make([]interface{}, len(val))
		for i, item := range val {
			sorted[i] = sortMapKeys(item)
		}
		return sorted
	default:
		return val
	}
}
