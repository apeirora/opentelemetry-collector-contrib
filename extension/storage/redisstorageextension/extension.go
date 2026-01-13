// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redisstorageextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/redisstorageextension"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.uber.org/zap"
)

type redisStorage struct {
	cfg    *Config
	logger *zap.Logger
	client *redis.Client
}

// Ensure this storage extension implements the appropriate interface
var _ storage.Extension = (*redisStorage)(nil)

func newRedisStorage(logger *zap.Logger, config *Config) (extension.Extension, error) {
	return &redisStorage{
		cfg:    config,
		logger: logger,
	}, nil
}

// Start runs cleanup if configured
func (rs *redisStorage) Start(ctx context.Context, _ component.Host) error {
	tlsConfig, err := rs.cfg.TLS.LoadTLSConfig(ctx)
	if err != nil {
		return err
	}

	maxRetries := 10
	retryDelay := 2 * time.Second
	var lastErr error

	time.Sleep(5 * time.Second)

	for attempt := 0; attempt < maxRetries; attempt++ {
		dialer := &net.Dialer{
			Timeout: 30 * time.Second,
		}

		c := redis.NewClient(&redis.Options{
			Addr:            rs.cfg.Endpoint,
			Password:        string(rs.cfg.Password),
			DB:              rs.cfg.DB,
			TLSConfig:       tlsConfig,
			Dialer:          dialer.DialContext,
			DialTimeout:     30 * time.Second,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			PoolTimeout:     30 * time.Second,
			MaxRetries:      0,
			MinRetryBackoff: 100 * time.Millisecond,
			MaxRetryBackoff: 2 * time.Second,
			PoolSize:        1,
			MinIdleConns:    0,
		})

		pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.Ping(pingCtx).Err()
		cancel()

		if err == nil {
			rs.client = c
			rs.logger.Info("Successfully connected to Redis", zap.String("endpoint", rs.cfg.Endpoint))
			return nil
		}

		c.Close()
		lastErr = err

		if attempt < maxRetries-1 {
			rs.logger.Info("Redis connection attempt failed, retrying...", zap.String("endpoint", rs.cfg.Endpoint), zap.Int("attempt", attempt+1), zap.Error(err))
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("failed to connect to Redis at %s after %d attempts: %w", rs.cfg.Endpoint, maxRetries, lastErr)
}

// Shutdown will close any open databases
func (rs *redisStorage) Shutdown(context.Context) error {
	if rs.client == nil {
		return nil
	}
	return rs.client.Close()
}

type redisClient struct {
	client     *redis.Client
	prefix     string
	expiration time.Duration
}

var _ storage.Client = redisClient{}

func (rc redisClient) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := rc.client.Get(ctx, rc.prefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return b, err
}

func (rc redisClient) Set(ctx context.Context, key string, value []byte) error {
	_, err := rc.client.Set(ctx, rc.prefix+key, value, rc.expiration).Result()
	return err
}

func (rc redisClient) Delete(ctx context.Context, key string) error {
	_, err := rc.client.Del(ctx, rc.prefix+key).Result()
	return err
}

func (rc redisClient) Batch(ctx context.Context, ops ...*storage.Operation) error {
	p := rc.client.Pipeline()
	for _, op := range ops {
		switch op.Type {
		case storage.Delete:
			p.Del(ctx, rc.prefix+op.Key)
		case storage.Set:
			p.Set(ctx, rc.prefix+op.Key, op.Value, rc.expiration)
		}
	}
	_, err := p.Exec(ctx)
	if err != nil {
		return err
	}
	// once the pipeline has been executed, we need to fetch all the values
	// and set them on the op
	for _, op := range ops {
		if op.Type == storage.Get {
			value, e := rc.client.Get(ctx, rc.prefix+op.Key).Bytes()
			if e != nil {
				if errors.Is(e, redis.Nil) {
					continue
				}
				return e
			}
			if value != nil {
				// the output of Bucket.Get is only valid within a transaction, so we need to make a copy
				// to be able to return the value
				op.Value = make([]byte, len(value))
				copy(op.Value, value)
			} else {
				op.Value = nil
			}
		}
	}
	return err
}

func (redisClient) Close(context.Context) error {
	return nil
}

// GetClient returns a storage client for an individual component
func (rs *redisStorage) GetClient(_ context.Context, kind component.Kind, ent component.ID, name string) (storage.Client, error) {
	return redisClient{
		client:     rs.client,
		prefix:     rs.getPrefix(ent, kindString(kind), name),
		expiration: rs.cfg.Expiration,
	}, nil
}

func (rs *redisStorage) getPrefix(ent component.ID, kind, name string) string {
	var prefix string
	if name == "" {
		prefix = fmt.Sprintf("%s_%s_%s", kind, ent.Type(), ent.Name())
	} else {
		prefix = fmt.Sprintf("%s_%s_%s_%s", kind, ent.Type(), ent.Name(), name)
	}

	if rs.cfg.Prefix != "" {
		prefix = fmt.Sprintf("%s_%s", prefix, rs.cfg.Prefix)
	}

	return prefix
}

func kindString(k component.Kind) string {
	switch k {
	case component.KindReceiver:
		return "receiver"
	case component.KindProcessor:
		return "processor"
	case component.KindExporter:
		return "exporter"
	case component.KindExtension:
		return "extension"
	case component.KindConnector:
		return "connector"
	default:
		return "other" // not expected
	}
}
