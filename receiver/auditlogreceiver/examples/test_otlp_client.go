package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

func main() {
	fmt.Println("OTLP Client Test for Audit Log Receiver")
	fmt.Println("=====================================")

	// Test endpoints
	endpoints := []string{
		"http://localhost:4310/v1/logs",
		"http://localhost:4310/v1/logs/",
		"http://localhost:4310/v1/logs/export",
	}

	// Test different scenarios
	testCases := []struct {
		name        string
		createFunc  func() []byte
		description string
	}{
		{
			name:        "Basic Log",
			createFunc:  createBasicLog,
			description: "Simple log record with basic attributes",
		},
		{
			name:        "Multiple Logs",
			createFunc:  createMultipleLogs,
			description: "Multiple log records in single request",
		},
		{
			name:        "Resource Attributes",
			createFunc:  createLogWithResourceAttrs,
			description: "Log with resource-level attributes",
		},
		{
			name:        "Empty Logs",
			createFunc:  createEmptyLogs,
			description: "Empty log request (should still work)",
		},
		{
			name:        "Error Log",
			createFunc:  createErrorLog,
			description: "Error-level log record",
		},
	}

	// Run tests
	for _, endpoint := range endpoints {
		fmt.Printf("\nTesting endpoint: %s\n", endpoint)
		fmt.Println(strings.Repeat("-", 50))

		for _, testCase := range testCases {
			fmt.Printf("\nTest: %s\n", testCase.name)
			fmt.Printf("Description: %s\n", testCase.description)

			// Create OTLP request
			requestData := testCase.createFunc()
			fmt.Printf("Request size: %d bytes\n", len(requestData))

			// Send request
			success := sendOTLPRequest(endpoint, requestData)
			if success {
				fmt.Println("✅ SUCCESS")
			} else {
				fmt.Println("❌ FAILED")
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("All tests completed!")
}

func createBasicLog() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	// Set log data
	logRecord.Body().SetStr("User login successful")
	logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord.SetSeverityText("INFO")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	// Add attributes
	attrs := logRecord.Attributes()
	attrs.PutStr("user.id", "john.doe")
	attrs.PutStr("event.type", "login")
	attrs.PutStr("source.ip", "192.168.1.100")

	return marshalOTLPRequest(logs)
}

func createMultipleLogs() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()

	// First log
	log1 := scopeLogs.LogRecords().AppendEmpty()
	log1.Body().SetStr("Application started")
	log1.SetSeverityNumber(plog.SeverityNumberInfo)
	log1.SetSeverityText("INFO")
	log1.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-5 * time.Minute)))

	// Second log
	log2 := scopeLogs.LogRecords().AppendEmpty()
	log2.Body().SetStr("Database connected")
	log2.SetSeverityNumber(plog.SeverityNumberInfo)
	log2.SetSeverityText("INFO")
	log2.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-4 * time.Minute)))

	// Third log
	log3 := scopeLogs.LogRecords().AppendEmpty()
	log3.Body().SetStr("API request processed")
	log3.SetSeverityNumber(plog.SeverityNumberInfo)
	log3.SetSeverityText("INFO")
	log3.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-3 * time.Minute)))

	return marshalOTLPRequest(logs)
}

func createLogWithResourceAttrs() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes
	resourceAttrs := resourceLogs.Resource().Attributes()
	resourceAttrs.PutStr("service.name", "audit-service")
	resourceAttrs.PutStr("service.version", "1.0.0")
	resourceAttrs.PutStr("deployment.environment", "production")
	resourceAttrs.PutStr("host.name", "audit-server-01")

	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	logRecord.Body().SetStr("Security audit: Permission changed")
	logRecord.SetSeverityNumber(plog.SeverityNumberWarn)
	logRecord.SetSeverityText("WARN")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	// Add log attributes
	attrs := logRecord.Attributes()
	attrs.PutStr("audit.event", "permission_change")
	attrs.PutStr("user.id", "admin")
	attrs.PutStr("target.user", "john.doe")

	return marshalOTLPRequest(logs)
}

func createEmptyLogs() []byte {
	logs := plog.NewLogs()
	return marshalOTLPRequest(logs)
}

func createErrorLog() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	logRecord.Body().SetStr("Database connection failed: timeout after 30s")
	logRecord.SetSeverityNumber(plog.SeverityNumberError)
	logRecord.SetSeverityText("ERROR")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	// Add error attributes
	attrs := logRecord.Attributes()
	attrs.PutStr("error.type", "timeout")
	attrs.PutStr("error.message", "Database connection timeout")
	attrs.PutStr("component", "database")

	return marshalOTLPRequest(logs)
}

func marshalOTLPRequest(logs plog.Logs) []byte {
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}
	return requestData
}

func sendOTLPRequest(endpoint string, requestData []byte) bool {
	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(requestData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return false
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", "otlp-test-client/1.0")

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return false
	}

	// Check response
	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Response size: %d bytes\n", len(body))
		return true
	} else {
		fmt.Printf("Error response: %s\n", string(body))
		return false
	}
}
