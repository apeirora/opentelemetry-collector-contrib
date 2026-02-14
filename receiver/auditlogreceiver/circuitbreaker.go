// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package auditlogreceiver

import (
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

type circuitBreakerState int

const (
	circuitClosed circuitBreakerState = iota
	circuitOpen
	circuitHalfOpen
)

type circuitBreaker struct {
	state            circuitBreakerState
	consecutiveFails int
	lastFailureTime  time.Time
	mutex            sync.RWMutex
	logger           *zap.Logger
	config           CircuitBreakerConfig
}

func newCircuitBreaker(config CircuitBreakerConfig, logger *zap.Logger) *circuitBreaker {
	return &circuitBreaker{
		state:  circuitClosed,
		config: config,
		logger: logger,
	}
}

func (cb *circuitBreaker) IsOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == circuitOpen {
		openDuration := cb.config.CircuitOpenDuration
		if openDuration == 0 {
			openDuration = time.Minute
		}
		if time.Since(cb.lastFailureTime) >= openDuration {
			cb.state = circuitHalfOpen
			cb.logger.Info("Circuit breaker transitioning to half-open state")
		}
		return cb.state == circuitOpen
	}
	return false
}

func (cb *circuitBreaker) IsHalfOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state == circuitHalfOpen
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.consecutiveFails = 0
	previousState := cb.state
	cb.state = circuitClosed

	if previousState == circuitHalfOpen {
		cb.logger.Info("Circuit breaker transitioned from half-open to closed due to successful operation")
	} else {
		cb.logger.Info("Circuit breaker closed due to successful operation")
	}
}

func (cb *circuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.consecutiveFails++
	cb.lastFailureTime = time.Now()

	threshold := cb.config.CircuitOpenThreshold
	if threshold == 0 {
		threshold = 5
	}

	if cb.state == circuitHalfOpen {
		cb.state = circuitOpen
		cb.logger.Warn("Circuit breaker reopened due to failure in half-open state",
			zap.Int("failures", cb.consecutiveFails))
	} else if cb.consecutiveFails >= threshold {
		cb.state = circuitOpen
		cb.logger.Warn("Circuit breaker opened due to consecutive failures",
			zap.Int("failures", cb.consecutiveFails))
	}
}

func (cb *circuitBreaker) getState() circuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

func (cb *circuitBreaker) shouldAttemptProcessing() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	return cb.state == circuitClosed || cb.state == circuitHalfOpen
}

// CheckAndUpdateState checks if the circuit breaker should transition states
func (cb *circuitBreaker) checkAndUpdateState() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if cb.state == circuitOpen {
		openDuration := cb.config.CircuitOpenDuration
		if openDuration == 0 {
			openDuration = time.Minute
		}
		if time.Since(cb.lastFailureTime) >= openDuration {
			cb.state = circuitHalfOpen
			cb.logger.Info("Circuit breaker transitioning to half-open state")
		}
	}
}

// checkCircuitBreakerState checks and updates circuit breaker state, returns true if processing should continue
func (cb *circuitBreaker) checkCircuitBreakerState(entryID string) (bool, error) {
	cb.checkAndUpdateState()

	if !cb.shouldAttemptProcessing() {
		return false, errors.New("circuit breaker is open, skipping processing")
	}

	state := cb.getState()
	switch state {
	case circuitHalfOpen:
		cb.logger.Debug("Processing log in half-open state to test connectivity", zap.String("id", entryID))
	case circuitClosed:
		cb.logger.Debug("Processing log in closed state (normal operation)", zap.String("id", entryID))
	}

	return true, nil
}
