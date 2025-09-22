package auditlogreceiver

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

type CircuitBreaker struct {
	state            CircuitBreakerState
	consecutiveFails int
	lastFailureTime  time.Time
	mutex            sync.RWMutex
	logger           *zap.Logger
	config           CircuitBreakerConfig
}

func NewCircuitBreaker(config CircuitBreakerConfig, logger *zap.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		state:  CircuitClosed,
		config: config,
		logger: logger,
	}
}

func (cb *CircuitBreaker) IsOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == CircuitOpen {
		openDuration := cb.config.CircuitOpenDuration
		if openDuration == 0 {
			openDuration = time.Minute
		}
		if time.Since(cb.lastFailureTime) >= openDuration {
			cb.state = CircuitHalfOpen
			cb.logger.Info("Circuit breaker transitioning to half-open state")
		}
		return cb.state == CircuitOpen
	}
	return false
}

func (cb *CircuitBreaker) IsHalfOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state == CircuitHalfOpen
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.consecutiveFails = 0
	previousState := cb.state
	cb.state = CircuitClosed

	if previousState == CircuitHalfOpen {
		cb.logger.Info("Circuit breaker transitioned from half-open to closed due to successful operation")
	} else {
		cb.logger.Info("Circuit breaker closed due to successful operation")
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.consecutiveFails++
	cb.lastFailureTime = time.Now()

	threshold := cb.config.CircuitOpenThreshold
	if threshold == 0 {
		threshold = 5
	}

	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
		cb.logger.Warn("Circuit breaker reopened due to failure in half-open state",
			zap.Int("failures", cb.consecutiveFails))
	} else if cb.consecutiveFails >= threshold {
		cb.state = CircuitOpen
		cb.logger.Warn("Circuit breaker opened due to consecutive failures",
			zap.Int("failures", cb.consecutiveFails))
	}
}

// for debugging/monitoring
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// for debugging/monitoring
func (cb *CircuitBreaker) GetConsecutiveFailures() int {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.consecutiveFails
}

func (cb *CircuitBreaker) ShouldAttemptProcessing() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	return cb.state == CircuitClosed || cb.state == CircuitHalfOpen
}

// CheckAndUpdateState checks if the circuit breaker should transition states
func (cb *CircuitBreaker) CheckAndUpdateState() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if cb.state == CircuitOpen {
		openDuration := cb.config.CircuitOpenDuration
		if openDuration == 0 {
			openDuration = time.Minute
		}
		if time.Since(cb.lastFailureTime) >= openDuration {
			cb.state = CircuitHalfOpen
			cb.logger.Info("Circuit breaker transitioning to half-open state")
		}
	}
}

// CheckCircuitBreakerState checks and updates circuit breaker state, returns true if processing should continue
func (cb *CircuitBreaker) CheckCircuitBreakerState(entryID string) (bool, error) {
	// Check and update circuit breaker state
	cb.CheckAndUpdateState()

	if !cb.ShouldAttemptProcessing() {
		return false, fmt.Errorf("circuit breaker is open, skipping processing")
	}

	// Log the circuit breaker state for debugging
	state := cb.GetState()
	if state == CircuitHalfOpen {
		cb.logger.Debug("Processing log in half-open state to test connectivity", zap.String("id", entryID))
	} else if state == CircuitClosed {
		cb.logger.Debug("Processing log in closed state (normal operation)", zap.String("id", entryID))
	}

	return true, nil
}
