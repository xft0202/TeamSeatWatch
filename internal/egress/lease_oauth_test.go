package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestRequiredLeaseQuarantinesExitDrift(t *testing.T) {
	var calls atomic.Int32
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			_, _ = w.Write([]byte("1.1.1.1"))
		default:
			_, _ = w.Write([]byte("8.8.8.8"))
		}
	}))
	defer echo.Close()
	key := []byte("integration-egress-key")
	firstIP := netip.MustParseAddr("8.8.8.8")
	fingerprint := Fingerprint(key, "7", firstIP)
	candidate := Candidate{ID: "candidate-1", Scheme: "http", Fingerprint: fingerprint}
	router := &Router{config: Config{Mode: ModeRequired, IPEchoURL: echo.URL, HMACKey: key, HMACKeyVersion: "7"}}
	manager := &LeaseManager{router: router, candidates: []Candidate{candidate}, active: map[[32]byte]struct{}{fingerprint: {}}}
	lease := &Lease{manager: manager, candidate: candidate, client: echo.Client(), mode: ModeRequired, fingerprint: fingerprint}
	if err := lease.Remeasure(context.Background()); !errors.Is(err, ErrEgressDrift) {
		t.Fatalf("remeasure err=%v want ErrEgressDrift", err)
	}
	if manager.ActiveCount() != 1 {
		t.Fatalf("drifted lease should remain active until release, active=%d", manager.ActiveCount())
	}
	lease.Release()
	if manager.ActiveCount() != 0 || len(manager.candidates) != 0 {
		t.Fatalf("drifted candidate was not released/quarantined: active=%d candidates=%d", manager.ActiveCount(), len(manager.candidates))
	}
}

func TestDirectLeaseDoesNotExposeProxyMetadata(t *testing.T) {
	router := &Router{config: Config{Mode: ModeDirect}}
	manager := &LeaseManager{router: router, active: make(map[[32]byte]struct{})}
	lease := &Lease{manager: manager, client: &http.Client{}, mode: ModeDirect}
	if lease.Scheme() != "" || lease.KeyVersion() != "" || lease.Fingerprint() != ([32]byte{}) || !lease.VerifiedAt().IsZero() {
		t.Fatalf("direct lease exposed proxy metadata: scheme=%q key=%q fingerprint=%x verified=%v", lease.Scheme(), lease.KeyVersion(), lease.Fingerprint(), lease.VerifiedAt())
	}
	if err := lease.Remeasure(context.Background()); err != nil {
		t.Fatalf("direct lease remeasure err=%v", err)
	}
}
