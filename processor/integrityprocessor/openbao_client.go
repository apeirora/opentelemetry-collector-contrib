// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrityprocessor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type openBaoClient struct {
	address   string
	token     string
	keyName   string
	mountPath string
	client    *http.Client
	logger    *zap.Logger
}

func newOpenBaoClient(config *OpenBaoTransitConfig, logger *zap.Logger) *openBaoClient {
	return &openBaoClient{
		address:   config.Address,
		token:     config.Token,
		keyName:   config.KeyName,
		mountPath: config.MountPath,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

type hmacRequest struct {
	Input     string `json:"input"`
	Algorithm string `json:"algorithm,omitempty"`
}

type hmacResponse struct {
	Data struct {
		HMAC string `json:"hmac"`
	} `json:"data"`
}

func (c *openBaoClient) signHMAC(ctx context.Context, data []byte, algorithm string) (string, error) {
	input := base64.StdEncoding.EncodeToString(data)
	
	reqBody := hmacRequest{
		Input: input,
	}
	
	if algorithm == "HMAC-SHA512" {
		reqBody.Algorithm = "sha2-512"
	} else {
		reqBody.Algorithm = "sha2-256"
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	
	url := fmt.Sprintf("%s/v1/%s/hmac/%s", c.address, c.mountPath, c.keyName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openbao returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var hmacResp hmacResponse
	if err := json.NewDecoder(resp.Body).Decode(&hmacResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	
	return hmacResp.Data.HMAC, nil
}
