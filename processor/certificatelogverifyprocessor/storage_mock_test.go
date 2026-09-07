// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"errors"
	"sync"

	"go.opentelemetry.io/collector/extension/xextension/storage"
)

type mapStorageClient struct {
	mu    sync.Mutex
	data  map[string][]byte
	closed bool
}

func newMapStorageClient() *mapStorageClient {
	return &mapStorageClient{data: make(map[string][]byte)}
}

func (c *mapStorageClient) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("client closed")
	}
	return c.data[key], nil
}

func (c *mapStorageClient) Set(_ context.Context, key string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client closed")
	}
	c.data[key] = value
	return nil
}

func (c *mapStorageClient) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client closed")
	}
	delete(c.data, key)
	return nil
}

func (c *mapStorageClient) Batch(_ context.Context, ops ...*storage.Operation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client closed")
	}
	for _, op := range ops {
		switch op.Type {
		case storage.Set:
			c.data[op.Key] = op.Value
		case storage.Delete:
			delete(c.data, op.Key)
		default:
			return errors.New("unsupported operation")
		}
	}
	return nil
}

func (c *mapStorageClient) Close(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
