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

func TestRequiredModeKeepsExplicitProxyTransportAndRejectsDirectClient(t *testing.T) {
	router, err := New(Config{
		Mode: ModeRequired,
		Endpoints: []Endpoint{
			{ID: "socks-local", URL: "socks5://127.0.0.1:1080"},
			{ID: "socks-remote-dns", URL: "socks5h://127.0.0.1:1081"},
			{ID: "http-auth", URL: "http://user:pass@127.0.0.1:8080"},
		},
		ReachabilityURL: "https://reach.example.test/",
		IPEchoURL:       "https://ip.example.test/",
		HMACKey:         []byte("egress-test-key"),
		HMACKeyVersion:  "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer router.CloseIdleConnections()

	if _, err := router.Client(); err == nil {
		t.Fatal("required mode returned a direct client")
	}
	for _, raw := range []string{
		"socks5://127.0.0.1:1080",
		"socks5h://127.0.0.1:1081",
		"http://user:pass@127.0.0.1:8080",
	} {
		parsed, err := parseEndpoint(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", parsed.scheme, err)
		}
		transport, err := router.transport(parsed)
		if err != nil {
			t.Fatalf("build %s transport: %v", parsed.scheme, err)
		}
		if parsed.scheme == "http" {
			if transport.Proxy == nil {
				t.Fatal("authenticated HTTP proxy was not configured")
			}
		} else if transport.Proxy != nil || transport.DialContext == nil {
			t.Fatalf("%s did not use its explicit SOCKS dial path", parsed.scheme)
		}
		transport.CloseIdleConnections()
	}
	if _, err := parseEndpoint("ftp://127.0.0.1:21"); err == nil {
		t.Fatal("unsupported proxy scheme was accepted")
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
