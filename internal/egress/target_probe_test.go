package egress

import (
	"context"
	"errors"
	"testing"
)

func TestRequiredModeNeverFallsBackWithoutVerifiedCapacity(t *testing.T) {
	router, err := New(Config{
		Mode:            ModeRequired,
		Endpoints:       []Endpoint{{ID: "proxy-1", URL: "http://127.0.0.1:1"}},
		ReachabilityURL: "https://example.com/health",
		IPEchoURL:       "https://example.com/ip",
		HMACKey:         []byte("ticket-05-test-key"), HMACKeyVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	leases, err := NewLeaseManager(router, Admission{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := leases.Acquire(context.Background())
	if lease != nil || !errors.Is(err, ErrLeaseExhausted) {
		t.Fatalf("required mode acquired an unverified or direct route: lease=%v err=%v", lease, err)
	}
}
