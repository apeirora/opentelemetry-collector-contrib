module test-auditlog

go 1.24

require (
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/collector/component v0.134.0
	go.opentelemetry.io/collector/consumer v0.134.0
	go.opentelemetry.io/collector/pdata/plog v1.40.0
	go.opentelemetry.io/collector/receiver v0.134.0
	go.uber.org/zap v1.27.0
)

replace github.com/open-telemetry/opentelemetry-collector-contrib/receiver/auditlogreceiver => ../receiver/auditlogreceiver
