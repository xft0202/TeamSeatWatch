package egress

import (
	"context"
	"sync"
)

// LeaseProvider is the narrow slice of egress the worker needs: one exclusive,
// already-verified exit for the duration of a platform attempt. Depending on
// this instead of *LeaseManager lets the Owner replace the whole pool at
// runtime, without restarting the worker or re-wiring call sites.
type LeaseProvider interface {
	Acquire(ctx context.Context) (*Lease, error)
	ActiveCount() int
}

// Manager owns the mutable current pool behind a stable LeaseProvider handle.
// A settings save swaps the pool atomically; in-flight leases finish against
// the pool they were acquired from, so a live platform attempt never changes
// exit mid-flight (ADR-0004 出口粘性).
type Manager struct {
	mu      sync.RWMutex
	current *LeaseManager
	status  Status
	base    Config
}

func NewManager(initial *LeaseManager, status Status, base Config) *Manager {
	return &Manager{current: initial, status: status, base: base}
}

// BaseConfig returns the deployment baseline (probe URLs, HMAC material,
// timeouts) so a settings save can rebuild only the provider choice on top.
func (m *Manager) BaseConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.base
}

func (m *Manager) Acquire(ctx context.Context) (*Lease, error) {
	m.mu.RLock()
	manager := m.current
	m.mu.RUnlock()
	if manager == nil {
		return nil, ErrLeaseExhausted
	}
	return manager.Acquire(ctx)
}

func (m *Manager) ActiveCount() int {
	m.mu.RLock()
	manager := m.current
	m.mu.RUnlock()
	if manager == nil {
		return 0
	}
	return manager.ActiveCount()
}

// Swap publishes a new pool. The caller builds it from the saved settings, so
// a swap is the only moment the pool changes.
func (m *Manager) Swap(next *LeaseManager, status Status) {
	m.mu.Lock()
	m.current = next
	m.status = status
	m.mu.Unlock()
}

// Status reports the redacted projection of the current pool.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}
