// Package settings owns the owner-editable runtime configuration snapshot.
// Deployment secrets (database DSN, TLS material, TOTP key ring path) stay in
// the environment; everything the owner can reasonably change lives here and is
// editable from the management UI without a restart.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
)

// Proxy is the owner-editable proxy configuration. Field set follows the
// reference implementation's config center: one provider plus its credentials,
// with an optional SOCKS5 list for the pasted-list workflow.
type Proxy struct {
	Provider string `json:"provider"` // cliproxy | b2proxy | proxy1024 | socks5 | direct
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Account  string `json:"account"`
	AuthMode string `json:"authMode"` // basic | rotating | list

	Country string `json:"country"`
	State   string `json:"state"`

	SessionLifetimeMin int      `json:"sessionLifetimeMin"`
	Socks5List         []string `json:"socks5List"`

	// Password is stored sealed; PasswordSet reports presence without echoing it.
	Password    string `json:"-"`
	PasswordSet bool   `json:"passwordSet"`
}

// Snapshot is the whole settings row.
type Snapshot struct {
	Version   int64
	Proxy     Proxy
	UpdatedAt string
	UpdatedBy string
}

// Store persists the singleton settings snapshot.
type Store struct {
	pool    *pgxpool.Pool
	keyRing auth.KeyRing
}

func NewStore(pool *pgxpool.Pool, keyRing auth.KeyRing) *Store {
	return &Store{pool: pool, keyRing: keyRing}
}

type proxyRow struct {
	Provider           string   `json:"provider"`
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Account            string   `json:"account"`
	AuthMode           string   `json:"authMode"`
	Country            string   `json:"country"`
	State              string   `json:"state"`
	SessionLifetimeMin int      `json:"sessionLifetimeMin"`
	Socks5List         []string `json:"socks5List"`
	PasswordVersion    uint16   `json:"passwordVersion"`
	PasswordNonce      []byte   `json:"passwordNonce"`
	PasswordCiphertext []byte   `json:"passwordCiphertext"`
}

// Load reads the snapshot and unseals the proxy password.
func (s *Store) Load(ctx context.Context) (Snapshot, error) {
	var version int64
	var raw []byte
	var updatedAt, updatedBy string
	err := s.pool.QueryRow(ctx, `SELECT version, proxy, updated_at::text, updated_by FROM tsw_settings WHERE id = true`).
		Scan(&version, &raw, &updatedAt, &updatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Snapshot{Version: 1}, nil
		}
		return Snapshot{}, err
	}
	var row proxyRow
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &row); err != nil {
			return Snapshot{}, err
		}
	}
	proxy := Proxy{
		Provider: row.Provider, Host: row.Host, Port: row.Port, Account: row.Account,
		AuthMode: row.AuthMode, Country: row.Country, State: row.State,
		SessionLifetimeMin: row.SessionLifetimeMin, Socks5List: row.Socks5List,
	}
	if len(row.PasswordCiphertext) > 0 && s.keyRing != nil {
		plaintext, err := auth.DecryptTOTP(row.PasswordVersion, row.PasswordNonce, row.PasswordCiphertext, s.keyRing)
		if err != nil {
			return Snapshot{}, fmt.Errorf("unseal proxy password: %w", err)
		}
		proxy.Password = string(plaintext)
		proxy.PasswordSet = true
	}
	if proxy.Provider == "" {
		proxy.Provider = "direct"
	}
	return Snapshot{Version: version, Proxy: proxy, UpdatedAt: updatedAt, UpdatedBy: updatedBy}, nil
}

// Save writes the snapshot atomically. An empty password keeps the stored one
// when keepPassword is set, so the UI never has to echo a secret back.
func (s *Store) Save(ctx context.Context, proxy Proxy, keepPassword bool) (Snapshot, error) {
	existing, err := s.loadRow(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	row := proxyRow{
		Provider: proxy.Provider, Host: proxy.Host, Port: proxy.Port, Account: proxy.Account,
		AuthMode: proxy.AuthMode, Country: proxy.Country, State: proxy.State,
		SessionLifetimeMin: proxy.SessionLifetimeMin, Socks5List: proxy.Socks5List,
	}
	if keepPassword && proxy.Password == "" {
		row.PasswordVersion = existing.PasswordVersion
		row.PasswordNonce = existing.PasswordNonce
		row.PasswordCiphertext = existing.PasswordCiphertext
	} else if proxy.Password != "" {
		version, nonce, ciphertext, err := auth.EncryptTOTP([]byte(proxy.Password), s.keyRing)
		if err != nil {
			return Snapshot{}, fmt.Errorf("seal proxy password: %w", err)
		}
		row.PasswordVersion = version
		row.PasswordNonce = nonce
		row.PasswordCiphertext = ciphertext
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return Snapshot{}, err
	}
	var savedVersion int64
	var updatedAt string
	err = s.pool.QueryRow(ctx, `
		UPDATE tsw_settings
		SET proxy = $1, version = version + 1, updated_at = now(), updated_by = 'owner'
		WHERE id = true
		RETURNING version, updated_at::text
	`, encoded).Scan(&savedVersion, &updatedAt)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: savedVersion, Proxy: proxy, UpdatedAt: updatedAt, UpdatedBy: "owner"}, nil
}

func (s *Store) loadRow(ctx context.Context) (proxyRow, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT proxy FROM tsw_settings WHERE id = true`).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return proxyRow{}, nil
		}
		return proxyRow{}, err
	}
	var row proxyRow
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &row); err != nil {
			return proxyRow{}, err
		}
	}
	return row, nil
}

// BuildEgressConfig turns the saved provider + credentials into the endpoint
// list the egress router admits. Only this function knows how the owner's
// fields map onto wire formats; the router keeps its own invariants.
func BuildEgressConfig(proxy Proxy, base egress.Config) (egress.Config, error) {
	config := base
	switch strings.ToLower(strings.TrimSpace(proxy.Provider)) {
	case "", "direct":
		config.Mode = egress.ModeDirect
		config.Endpoints = nil
		return config, nil
	case "socks5":
		urls := normalizeSocks5List(proxy.Socks5List)
		if len(urls) == 0 {
			return egress.Config{}, errors.New("socks5_list_empty")
		}
		config.Mode = egress.ModeRequired
		config.Endpoints = endpointsFromURLs(urls)
		return config, nil
	case "cliproxy", "b2proxy", "proxy1024":
		if strings.TrimSpace(proxy.Host) == "" || proxy.Port <= 0 {
			return egress.Config{}, errors.New("proxy_host_missing")
		}
		scheme := "socks5h"
		if strings.EqualFold(proxy.Provider, "b2proxy") || strings.EqualFold(proxy.Provider, "proxy1024") {
			scheme = "http"
		}
		built := scheme + "://"
		if proxy.Account != "" {
			built += url.UserPassword(proxy.Account, proxy.Password).String() + "@"
		}
		built += fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
		config.Mode = egress.ModeRequired
		config.Endpoints = endpointsFromURLs([]string{built})
		return config, nil
	default:
		return egress.Config{}, errors.New("proxy_provider_unknown")
	}
}

// Probe defaults are product constants, not deployment config: the owner should
// not have to supply probe URLs in .env just to switch proxies on. Overrides
// still win when a deployment provides them.
const (
	defaultReachabilityURL = "https://chatgpt.com/robots.txt"
	defaultIPEchoURL       = "https://api.ipify.org"
	defaultHMACKeyVersion  = "v1"
)

// FillProbeDefaults completes a required-mode config with the built-in probe
// targets and, falling back to a per-install key derived from the deployment
// key ring, so exit fingerprints stay domain-separated without extra .env knobs.
func FillProbeDefaults(config egress.Config, keyRing auth.KeyRing) egress.Config {
	if config.ReachabilityURL == "" {
		config.ReachabilityURL = defaultReachabilityURL
	}
	if config.IPEchoURL == "" {
		config.IPEchoURL = defaultIPEchoURL
	}
	if config.HMACKeyVersion == "" {
		config.HMACKeyVersion = defaultHMACKeyVersion
	}
	if len(config.HMACKey) == 0 && keyRing != nil {
		_, key := keyRing.Current()
		config.HMACKey = key[:]
	}
	return config
}

func endpointsFromURLs(urls []string) []egress.Endpoint {
	endpoints := make([]egress.Endpoint, 0, len(urls))
	for i, raw := range urls {
		endpoints = append(endpoints, egress.Endpoint{ID: fmt.Sprintf("owner-%d", i+1), URL: raw})
	}
	return endpoints
}

// normalizeSocks5List accepts both pasted shapes: socks5://user:pass@host:port
// and host:port:user:pass, mirroring the reference project's paste workflow.
func normalizeSocks5List(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "://") {
			out = append(out, trimmed)
			continue
		}
		parts := strings.Split(trimmed, ":")
		if len(parts) == 4 {
			out = append(out, fmt.Sprintf("socks5://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1]))
			continue
		}
		out = append(out, "socks5://"+trimmed)
	}
	return out
}
