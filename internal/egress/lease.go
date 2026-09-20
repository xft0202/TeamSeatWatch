package egress

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	ErrLeaseExhausted = errors.New("proxy_capacity_exhausted")
	ErrLeaseReleased  = errors.New("egress_lease_released")
	ErrEgressDrift    = errors.New("proxy_egress_drift")
)

// Lease binds one attempt to one admitted route. Release is explicit: closing
// HTTP connections must never make the same measured exit available early.
type Lease struct {
	manager     *LeaseManager
	candidate   Candidate
	client      *http.Client
	mode        Mode
	fingerprint [32]byte
	verifiedAt  time.Time
	mu          sync.Mutex
	released    bool
}

func (l *Lease) Mode() Mode           { return l.mode }
func (l *Lease) Client() *http.Client { return l.client }
func (l *Lease) Scheme() string       { return l.candidate.Scheme }
func (l *Lease) KeyVersion() string {
	if l.mode != ModeRequired || l.manager == nil {
		return ""
	}
	return l.manager.router.config.HMACKeyVersion
}
func (l *Lease) VerifiedAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verifiedAt
}
func (l *Lease) Fingerprint() [32]byte { return l.fingerprint }
func (l *Lease) Candidate() Candidate  { return l.candidate }

// Release returns required-mode capacity exactly once. Direct leases own no fingerprint.
func (l *Lease) Release() {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	l.mu.Unlock()
	l.client.CloseIdleConnections()
	if l.manager != nil && l.mode == ModeRequired {
		l.manager.release(l.fingerprint)
	}
}

// Remeasure verifies that a later platform stage still uses the originally leased exit.
func (l *Lease) Remeasure(ctx context.Context) error {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return ErrLeaseReleased
	}
	l.mu.Unlock()
	if l.mode == ModeDirect {
		return nil
	}
	body, err := probeBody(ctx, l.client, l.manager.router.config.IPEchoURL)
	if err != nil {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	addr, err := NormalizePublicIP(body)
	if err != nil {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	measured := Fingerprint(l.manager.router.config.HMACKey, l.manager.router.config.HMACKeyVersion, addr)
	if subtle.ConstantTimeCompare(measured[:], l.fingerprint[:]) != 1 {
		l.manager.exclude(l.fingerprint)
		return ErrEgressDrift
	}
	l.mu.Lock()
	l.verifiedAt = time.Now().UTC()
	l.mu.Unlock()
	return nil
}

// LeaseManager provides the ADR-0004 in-process exclusion boundary for a single worker.
type LeaseManager struct {
	router     *Router
	mu         sync.Mutex
	candidates []Candidate
	active     map[[32]byte]struct{}
}

func NewLeaseManager(router *Router, admission Admission) (*LeaseManager, error) {
	if router == nil {
		return nil, errors.New("egress router is required")
	}
	manager := &LeaseManager{router: router, active: make(map[[32]byte]struct{})}
	if router.config.Mode == ModeRequired {
		manager.candidates = append(manager.candidates, admission.Candidates...)
	}
	return manager, nil
}

// Acquire never falls back and remeasures required candidates before their
// first business request. Drifted routes are quarantined until the next process admission.
func (m *LeaseManager) Acquire(ctx context.Context) (*Lease, error) {
	if m.router.config.Mode == ModeDirect {
		client, err := m.router.Client()
		if err != nil {
			return nil, err
		}
		return &Lease{manager: m, client: client, mode: ModeDirect}, nil
	}
	drifted := false
	for {
		m.mu.Lock()
		var selected *Candidate
		for index := range m.candidates {
			candidate := m.candidates[index]
			if _, used := m.active[candidate.Fingerprint]; used {
				continue
			}
			selected = &candidate
			m.active[candidate.Fingerprint] = struct{}{}
			break
		}
		m.mu.Unlock()
		if selected == nil {
			if drifted {
				return nil, ErrEgressDrift
			}
			return nil, ErrLeaseExhausted
		}
		client, err := m.router.ClientFor(*selected)
		if err != nil {
			m.quarantine(selected.Fingerprint)
			continue
		}
		lease := &Lease{
			manager: m, candidate: *selected, client: client, mode: ModeRequired,
			fingerprint: selected.Fingerprint, verifiedAt: selected.VerifiedAt,
		}
		if err := lease.Remeasure(ctx); err != nil {
			drifted = true
			lease.Release()
			continue
		}
		return lease, nil
	}
}

func (m *LeaseManager) quarantine(fingerprint [32]byte) {
	m.mu.Lock()
	delete(m.active, fingerprint)
	m.excludeLocked(fingerprint)
	m.mu.Unlock()
}

func (m *LeaseManager) exclude(fingerprint [32]byte) {
	m.mu.Lock()
	m.excludeLocked(fingerprint)
	m.mu.Unlock()
}

func (m *LeaseManager) excludeLocked(fingerprint [32]byte) {
	for index, candidate := range m.candidates {
		if candidate.Fingerprint == fingerprint {
			m.candidates = append(m.candidates[:index], m.candidates[index+1:]...)
			break
		}
	}
}

func (m *LeaseManager) release(fingerprint [32]byte) {
	m.mu.Lock()
	delete(m.active, fingerprint)
	m.mu.Unlock()
}

func (m *LeaseManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}
