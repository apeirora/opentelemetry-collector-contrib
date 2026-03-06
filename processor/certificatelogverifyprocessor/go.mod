module github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatelogverifyprocessor

go 1.25.0

require (
	go.opentelemetry.io/collector/component v1.53.0
	go.opentelemetry.io/collector/consumer v1.53.0
	go.opentelemetry.io/collector/pdata v1.53.0
	go.opentelemetry.io/collector/processor v1.53.0
	go.uber.org/zap v1.27.1
	k8s.io/apimachinery v0.35.2
	k8s.io/client-go v0.35.2
)
