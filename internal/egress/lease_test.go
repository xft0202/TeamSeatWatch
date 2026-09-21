package egress

import (
	"crypto/sha256"
	"net/http"
	"testing"
)

func TestLeaseManagerDuplicateFingerprintCapacityAndRelease(t *testing.T) {
	fingerprint := sha256.Sum256([]byte("same-exit"))
	manager := &LeaseManager{active: map[[32]byte]struct{}{}}
	manager.active[fingerprint] = struct{}{}
	manager.active[fingerprint] = struct{}{}
	if got := manager.ActiveCount(); got != 1 {
		t.Fatalf("duplicate fingerprint consumed more than one capacity slot: got %d", got)
	}
	lease := &Lease{manager: manager, client: &http.Client{}, mode: ModeRequired, fingerprint: fingerprint}
	lease.Release()
	lease.Release()
	if got := manager.ActiveCount(); got != 0 {
		t.Fatalf("released fingerprint remained active: got %d", got)
	}
}
