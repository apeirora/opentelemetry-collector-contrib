// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"crypto/x509"

	"go.uber.org/zap"
)

func supportedIntegrityAlgorithms(hmacLoaded, certLoaded bool) []string {
	var algs []string
	if hmacLoaded {
		algs = append(algs, algoHMACSHA256, algoHMACSHA512)
	}
	if certLoaded {
		algs = append(algs, algoECDSAP256SHA256, algoRSAPKCS1SHA256)
	}
	return algs
}

func loadSyncVerificationKeys(cfg *Config, logger *zap.Logger) ([]byte, *x509.Certificate, error) {
	var hmacKey []byte
	var cert *x509.Certificate

	if cfg.hasHMACKeySource() {
		key, err := loadHMACKey(cfg)
		if err != nil {
			return nil, nil, err
		}
		hmacKey = key
		source := cfg.HmacKeyFile
		if source == "" && cfg.K8sSecret != nil {
			source = cfg.K8sSecret.Namespace + "/" + cfg.K8sSecret.Name + "#" + cfg.K8sSecret.HMACKeyEntry
		}
		logger.Info("Loaded HMAC key for audit log verification", zap.String("source", source))
	}

	if cfg.hasCertKeySource() {
		loaded, err := loadCertificate(cfg)
		if err != nil {
			return nil, nil, err
		}
		cert = loaded
		source := cfg.CertFile
		if source == "" && cfg.K8sSecret != nil {
			source = cfg.K8sSecret.Namespace + "/" + cfg.K8sSecret.Name + "#" + cfg.K8sSecret.CertKeyEntry
		}
		logger.Info("Loaded certificate for audit log signature verification", zap.String("source", source))
	}

	logVerificationCapabilities(logger, len(hmacKey) > 0, cert != nil)
	return hmacKey, cert, nil
}

func logVerificationCapabilities(logger *zap.Logger, hmacLoaded, certLoaded bool) {
	algs := supportedIntegrityAlgorithms(hmacLoaded, certLoaded)
	logger.Info("Audit integrity verification ready",
		zap.Bool("hmac_key_loaded", hmacLoaded),
		zap.Bool("certificate_loaded", certLoaded),
		zap.Strings("supported_algorithms", algs),
	)
	if hmacLoaded && !certLoaded {
		logger.Warn("Incoming signature algorithms will be rejected until a certificate is configured",
			zap.Strings("unsupported_algorithms", []string{algoECDSAP256SHA256, algoRSAPKCS1SHA256}),
		)
	}
	if certLoaded && !hmacLoaded {
		logger.Warn("Incoming HMAC algorithms will be rejected until an HMAC key is configured",
			zap.Strings("unsupported_algorithms", []string{algoHMACSHA256, algoHMACSHA512}),
		)
	}
}
