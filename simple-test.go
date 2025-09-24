package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("🧪 Testing AuditLog Receiver")
	fmt.Println("")

	// Test data
	testData := map[string]interface{}{
		"resource":  "system",
		"timestamp": time.Now().Format("2006-01-02T15:04:05Z"),
		"user":      "test-user",
		"action":    "login",
		"details": map[string]interface{}{
			"ip":         "192.168.1.100",
			"user_agent": "test-client",
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(testData)
	if err != nil {
		fmt.Printf("❌ Error marshaling JSON: %v\n", err)
		return
	}

	fmt.Printf("📤 Sending test data:\n%s\n\n", string(jsonData))

	// Send POST request
	resp, err := http.Post("http://localhost:4310/v1/logs", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("❌ Error sending request: %v\n", err)
		fmt.Println("Make sure the audit log receiver is running on port 4310")
		return
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ Error reading response: %v\n", err)
		return
	}

	fmt.Printf("📥 Response Status: %s\n", resp.Status)
	fmt.Printf("📥 Response Body: %s\n", string(body))

	if resp.StatusCode == 200 {
		fmt.Println("✅ Test successful!")
	} else {
		fmt.Printf("❌ Test failed with status: %s\n", resp.Status)
	}
}
