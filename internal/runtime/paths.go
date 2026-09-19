package runtime

import "time"

const (
	ownerRoute          = "/owner"
	publicRoute         = "/redeem"
	privateHealthPath   = "/internal/v1/health"
	livePath            = "/health/live"
	readyPath           = "/health/ready"
	metricsPath         = "/metrics"
	requestIDHeader     = "X-Request-ID"
	maxRequestIDLength  = 64
	defaultProbeTimeout = time.Second
)
