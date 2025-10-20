// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

func main() {
	// Example 1: Basic OTLP request with a single log record
	fmt.Println("=== Example 1: Basic OTLP Request ===")
	basicRequest := createBasicOTLPRequest()
	sendOTLPRequest("http://localhost:4310/v1/logs", basicRequest)

	// Example 2: OTLP request with multiple log records
	fmt.Println("\n=== Example 2: Multiple Log Records ===")
	multiRequest := createMultiLogOTLPRequest()
	sendOTLPRequest("http://localhost:4310/v1/logs", multiRequest)

	// Example 3: OTLP request with resource attributes
	fmt.Println("\n=== Example 3: With Resource Attributes ===")
	resourceRequest := createResourceAttributesOTLPRequest()
	sendOTLPRequest("http://localhost:4310/v1/logs", resourceRequest)

	// Example 4: OTLP request with scope attributes
	fmt.Println("\n=== Example 4: With Scope Attributes ===")
	scopeRequest := createScopeAttributesOTLPRequest()
	sendOTLPRequest("http://localhost:4310/v1/logs", scopeRequest)

	// Example 5: OTLP request with different severity levels
	fmt.Println("\n=== Example 5: Different Severity Levels ===")
	severityRequest := createSeverityLevelsOTLPRequest()
	sendOTLPRequest("http://localhost:4310/v1/logs", severityRequest)
}

// createBasicOTLPRequest creates a simple OTLP request with one log record
func createBasicOTLPRequest() []byte {
	// Create logs
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	// Set log record data
	logRecord.Body().SetStr("User authentication successful for user: john.doe")
	logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord.SetSeverityText("INFO")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	// Add some attributes
	attrs := logRecord.Attributes()
	attrs.PutStr("user.id", "john.doe")
	attrs.PutStr("event.type", "authentication")
	attrs.PutStr("service.name", "auth-service")
	attrs.PutInt("user.session.duration", 3600)

	// Create OTLP request
	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}

	return requestData
}

// createMultiLogOTLPRequest creates an OTLP request with multiple log records
func createMultiLogOTLPRequest() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()

	// First log record
	logRecord1 := scopeLogs.LogRecords().AppendEmpty()
	logRecord1.Body().SetStr("Application started successfully")
	logRecord1.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord1.SetSeverityText("INFO")
	logRecord1.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-5 * time.Minute)))

	attrs1 := logRecord1.Attributes()
	attrs1.PutStr("component", "application")
	attrs1.PutStr("phase", "startup")

	// Second log record
	logRecord2 := scopeLogs.LogRecords().AppendEmpty()
	logRecord2.Body().SetStr("Database connection established")
	logRecord2.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord2.SetSeverityText("INFO")
	logRecord2.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-4 * time.Minute)))

	attrs2 := logRecord2.Attributes()
	attrs2.PutStr("component", "database")
	attrs2.PutStr("connection.pool.size", "10")

	// Third log record
	logRecord3 := scopeLogs.LogRecords().AppendEmpty()
	logRecord3.Body().SetStr("Failed to process request: timeout")
	logRecord3.SetSeverityNumber(plog.SeverityNumberError)
	logRecord3.SetSeverityText("ERROR")
	logRecord3.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-2 * time.Minute)))

	attrs3 := logRecord3.Attributes()
	attrs3.PutStr("error.type", "timeout")
	attrs3.PutStr("request.id", "req-12345")

	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}

	return requestData
}

// createResourceAttributesOTLPRequest creates an OTLP request with resource attributes
func createResourceAttributesOTLPRequest() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()

	// Set resource attributes
	resourceAttrs := resourceLogs.Resource().Attributes()
	resourceAttrs.PutStr("service.name", "audit-service")
	resourceAttrs.PutStr("service.version", "1.2.3")
	resourceAttrs.PutStr("deployment.environment", "production")
	resourceAttrs.PutStr("host.name", "audit-server-01")
	resourceAttrs.PutStr("host.ip", "192.168.1.100")
	resourceAttrs.PutStr("k8s.namespace", "audit")
	resourceAttrs.PutStr("k8s.pod.name", "audit-pod-abc123")

	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	logRecord.Body().SetStr("Security audit: User permission changed")
	logRecord.SetSeverityNumber(plog.SeverityNumberWarn)
	logRecord.SetSeverityText("WARN")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	attrs := logRecord.Attributes()
	attrs.PutStr("audit.event", "permission_change")
	attrs.PutStr("user.id", "admin")
	attrs.PutStr("target.user", "john.doe")
	attrs.PutStr("permission.old", "read")
	attrs.PutStr("permission.new", "write")

	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}

	return requestData
}

// createScopeAttributesOTLPRequest creates an OTLP request with scope attributes
func createScopeAttributesOTLPRequest() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()

	// Set scope attributes
	scopeAttrs := scopeLogs.Scope().Attributes()
	scopeAttrs.PutStr("scope.name", "audit-logger")
	scopeAttrs.PutStr("scope.version", "2.1.0")
	scopeAttrs.PutStr("logger.name", "com.company.audit")

	logRecord := scopeLogs.LogRecords().AppendEmpty()
	logRecord.Body().SetStr("API access logged: GET /api/users")
	logRecord.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord.SetSeverityText("INFO")
	logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	attrs := logRecord.Attributes()
	attrs.PutStr("http.method", "GET")
	attrs.PutStr("http.url", "/api/users")
	attrs.PutStr("http.status_code", "200")
	attrs.PutStr("user.agent", "Mozilla/5.0...")
	attrs.PutStr("client.ip", "203.0.113.1")

	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}

	return requestData
}

// createSeverityLevelsOTLPRequest creates an OTLP request with different severity levels
func createSeverityLevelsOTLPRequest() []byte {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()

	// TRACE level
	logRecord1 := scopeLogs.LogRecords().AppendEmpty()
	logRecord1.Body().SetStr("Detailed trace: Function entry")
	logRecord1.SetSeverityNumber(plog.SeverityNumberTrace)
	logRecord1.SetSeverityText("TRACE")
	logRecord1.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-10 * time.Minute)))

	// DEBUG level
	logRecord2 := scopeLogs.LogRecords().AppendEmpty()
	logRecord2.Body().SetStr("Debug: Processing configuration")
	logRecord2.SetSeverityNumber(plog.SeverityNumberDebug)
	logRecord2.SetSeverityText("DEBUG")
	logRecord2.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-8 * time.Minute)))

	// INFO level
	logRecord3 := scopeLogs.LogRecords().AppendEmpty()
	logRecord3.Body().SetStr("Information: Service health check passed")
	logRecord3.SetSeverityNumber(plog.SeverityNumberInfo)
	logRecord3.SetSeverityText("INFO")
	logRecord3.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-6 * time.Minute)))

	// WARN level
	logRecord4 := scopeLogs.LogRecords().AppendEmpty()
	logRecord4.Body().SetStr("Warning: High memory usage detected")
	logRecord4.SetSeverityNumber(plog.SeverityNumberWarn)
	logRecord4.SetSeverityText("WARN")
	logRecord4.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-4 * time.Minute)))

	// ERROR level
	logRecord5 := scopeLogs.LogRecords().AppendEmpty()
	logRecord5.Body().SetStr("Error: Database connection failed")
	logRecord5.SetSeverityNumber(plog.SeverityNumberError)
	logRecord5.SetSeverityText("ERROR")
	logRecord5.SetTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-2 * time.Minute)))

	// FATAL level
	logRecord6 := scopeLogs.LogRecords().AppendEmpty()
	logRecord6.Body().SetStr("Fatal: System shutdown initiated")
	logRecord6.SetSeverityNumber(plog.SeverityNumberFatal)
	logRecord6.SetSeverityText("FATAL")
	logRecord6.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

	otlpReq := plogotlp.NewExportRequestFromLogs(logs)
	requestData, err := otlpReq.MarshalProto()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal OTLP request: %v", err))
	}

	return requestData
}

// sendOTLPRequest sends an OTLP request to the specified endpoint
func sendOTLPRequest(endpoint string, requestData []byte) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(requestData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", "otlp-example-client/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("Response Body Length: %d bytes\n", len(body))

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Response Body: %s\n", string(body))
	} else {
		fmt.Println("Request sent successfully!")
	}
	fmt.Println()
}
