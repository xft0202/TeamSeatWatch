package egress

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	ModeDirect   Mode = "direct"
	ModeRequired Mode = "required"

	maxProbeBody       = 256
	fingerprintDomain  = "teamseatwatch-egress-v1\x00"
	defaultDialTimeout = 3 * time.Second
	defaultTLSTimeout  = 3 * time.Second
	defaultHeaderLimit = 5 * time.Second
	defaultIdleTimeout = 30 * time.Second
	defaultRequestTime = 10 * time.Second
)

// Mode identifies whether platform traffic is explicitly direct or must use an admitted proxy.
type Mode string

// Endpoint is a deployment-supplied proxy with a stable, non-secret identifier.
type Endpoint struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Config is the immutable egress policy assembled at the control-process boundary.
// Endpoint URLs and HMAC material must never leave this package through status or errors.
type Config struct {
	Mode            Mode
	Endpoints       []Endpoint
	ReachabilityURL string
	IPEchoURL       string
	HMACKey         []byte
	HMACKeyVersion  string
	DialTimeout     time.Duration
	TLSHandshake    time.Duration
	ResponseHeader  time.Duration
	IdleConn        time.Duration
	RequestTimeout  time.Duration
	Resolver        *net.Resolver
	TLSClientConfig *tls.Config
}

// ConfigError exposes a stable diagnostic code without embedding endpoint details.
type ConfigError struct{ code string }

func (e *ConfigError) Error() string { return e.code }

func (e *ConfigError) Code() string { return e.code }

// ErrorCode converts internal egress failures to the small public diagnostic vocabulary.
func ErrorCode(err error) string {
	var configErr *ConfigError
	if errors.As(err, &configErr) {
		return configErr.code
	}
	return "egress_failure"
}

func configError(code string) error { return &ConfigError{code: code} }

// ParseMode rejects implicit routing so a missing deployment choice cannot become direct traffic.
func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case ModeDirect:
		return ModeDirect, nil
	case ModeRequired:
		return ModeRequired, nil
	default:
		return "", configError("egress_mode_invalid")
	}
}

// ConfigFromEnv parses only deployment configuration. It never reads proxy
// environment variables or the process-wide HTTP client.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, configError("egress_config_invalid")
	}
	if getenv("TSW_EGRESS_PROXY") != "" || getenv("TSW_PROXY_URL") != "" {
		return Config{}, configError("egress_unknown_config")
	}
	mode, err := ParseMode(getenv("TSW_EGRESS_MODE"))
	if err != nil {
		return Config{}, err
	}
	config := Config{Mode: mode}
	if mode == ModeDirect {
		if getenv("TSW_EGRESS_ENDPOINTS") != "" || getenv("TSW_EGRESS_REACHABILITY_URL") != "" || getenv("TSW_EGRESS_IP_ECHO_URL") != "" || getenv("TSW_EGRESS_HMAC_KEY") != "" || getenv("TSW_EGRESS_HMAC_KEY_VERSION") != "" {
			return Config{}, configError("egress_direct_config_invalid")
		}
		return config, nil
	}
	if err := json.Unmarshal([]byte(getenv("TSW_EGRESS_ENDPOINTS")), &config.Endpoints); err != nil || len(config.Endpoints) == 0 {
		return Config{}, configError("egress_required_config_missing")
	}
	config.ReachabilityURL = getenv("TSW_EGRESS_REACHABILITY_URL")
	config.IPEchoURL = getenv("TSW_EGRESS_IP_ECHO_URL")
	config.HMACKey = []byte(getenv("TSW_EGRESS_HMAC_KEY"))
	config.HMACKeyVersion = getenv("TSW_EGRESS_HMAC_KEY_VERSION")
	return config, nil
}

// Candidate is an in-memory proxy route that passed both reachability and public-exit checks.
// Its endpoint and full fingerprint remain private because both are sensitive operational data.
type Candidate struct {
	ID          string
	Scheme      string
	Fingerprint [sha256.Size]byte
	VerifiedAt  time.Time
	endpoint    Endpoint
}

// Failure records only the stable class needed for low-cardinality status reporting.
type Failure struct {
	ID     string
	Scheme string
	Code   string
}

// Admission is the complete result of one bounded candidate validation pass.
type Admission struct {
	Candidates  []Candidate
	Failures    []Failure
	ValidatedAt time.Time
}

// UniqueExitCount reports capacity after candidates sharing a measured exit are deduplicated.
func (a Admission) UniqueExitCount() int { return len(a.Candidates) }

// Status is the redacted projection permitted on the private metrics boundary.
type Status struct {
	Policy           Mode
	AdmittedByScheme map[string]int
	UniqueExitCount  int
	FailureClasses   map[string]int
	ValidatedAt      time.Time
}

// PlatformClients is the runtime boundary for all future platform traffic.
// Required mode cannot return a client until its candidate passed admission.
type PlatformClients interface {
	Client() (*http.Client, error)
	ClientFor(Candidate) (*http.Client, error)
	CloseIdleConnections()
}

// Router owns immutable transport policy and the candidates admitted by a
// bounded, no-credential probe. It intentionally does not own task leases.
type Router struct {
	config     Config
	candidates map[string]Candidate
	mu         sync.Mutex
	transports map[*http.Transport]struct{}
}

// New validates immutable policy and endpoint syntax without making network calls.
// Required-mode callers must complete Admit before requesting a platform client.
func New(config Config) (*Router, error) {
	if config.Mode != ModeDirect && config.Mode != ModeRequired {
		return nil, configError("egress_mode_invalid")
	}
	if config.Mode == ModeDirect {
		if len(config.Endpoints) != 0 || config.ReachabilityURL != "" || config.IPEchoURL != "" || len(config.HMACKey) != 0 || config.HMACKeyVersion != "" {
			return nil, configError("egress_direct_config_invalid")
		}
		return &Router{config: withDefaults(config), transports: make(map[*http.Transport]struct{})}, nil
	}
	if len(config.Endpoints) == 0 || config.ReachabilityURL == "" || config.IPEchoURL == "" || len(config.HMACKey) == 0 || config.HMACKeyVersion == "" {
		return nil, configError("egress_required_config_missing")
	}
	if err := validateProbeURL(config.ReachabilityURL); err != nil {
		return nil, configError("egress_reachability_url_invalid")
	}
	if err := validateProbeURL(config.IPEchoURL); err != nil {
		return nil, configError("egress_ip_echo_url_invalid")
	}
	endpoints := make(map[string]Endpoint, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if endpoint.ID == "" || endpoints[endpoint.ID] != (Endpoint{}) {
			return nil, configError("egress_endpoint_id_invalid")
		}
		if _, err := parseEndpoint(endpoint.URL); err != nil {
			return nil, err
		}
		endpoints[endpoint.ID] = endpoint
	}
	config = withDefaults(config)
	return &Router{config: config, candidates: make(map[string]Candidate), transports: make(map[*http.Transport]struct{})}, nil
}

func withDefaults(config Config) Config {
	if config.DialTimeout <= 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.TLSHandshake <= 0 {
		config.TLSHandshake = defaultTLSTimeout
	}
	if config.ResponseHeader <= 0 {
		config.ResponseHeader = defaultHeaderLimit
	}
	if config.IdleConn <= 0 {
		config.IdleConn = defaultIdleTimeout
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = defaultRequestTime
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	return config
}

func validateProbeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid")
	}
	return nil
}

type endpointURL struct {
	u        *url.URL
	username string
	password string
	hasAuth  bool
	scheme   string
}

func parseEndpoint(raw string) (endpointURL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Port() == "" || !ParsePort(u.Port()) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return endpointURL{}, configError("egress_endpoint_invalid")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return endpointURL{}, configError("egress_scheme_unsupported")
	}
	result := endpointURL{u: u, scheme: scheme}
	if u.User != nil {
		password, ok := u.User.Password()
		if !ok || u.User.Username() == "" || password == "" {
			return endpointURL{}, configError("egress_auth_invalid")
		}
		result.username, result.password, result.hasAuth = u.User.Username(), password, true
	}
	return result, nil
}

// Admit measures every configured route and atomically replaces the usable candidate set.
// An empty required-mode set is an explicit failure; it never falls back to direct transport.
func (r *Router) Admit(ctx context.Context) (Admission, error) {
	validatedAt := time.Now().UTC()
	if r.config.Mode == ModeDirect {
		return Admission{ValidatedAt: validatedAt}, nil
	}
	admission := Admission{}
	nextCandidates := make(map[string]Candidate)
	for _, endpoint := range r.config.Endpoints {
		candidate, code := r.probe(ctx, endpoint)
		if code != "" {
			parsed, _ := parseEndpoint(endpoint.URL)
			admission.Failures = append(admission.Failures, Failure{ID: endpoint.ID, Scheme: parsed.scheme, Code: code})
			continue
		}
		key := string(candidate.Fingerprint[:])
		if _, exists := nextCandidates[key]; exists {
			admission.Failures = append(admission.Failures, Failure{ID: endpoint.ID, Scheme: candidate.Scheme, Code: "egress_duplicate_exit"})
			continue
		}
		nextCandidates[key] = candidate
		admission.Candidates = append(admission.Candidates, candidate)
	}
	admission.ValidatedAt = time.Now().UTC()
	r.mu.Lock()
	r.candidates = nextCandidates
	r.mu.Unlock()
	if len(admission.Candidates) == 0 {
		return admission, configError("proxy_capacity_exhausted")
	}
	return admission, nil
}

// Status projects admission into fixed protocol and failure categories. It deliberately
// omits endpoint identities, proxy hosts, observed IPs, credentials, and fingerprints.
func (r *Router) Status(admission Admission) Status {
	status := Status{
		Policy:           r.config.Mode,
		AdmittedByScheme: map[string]int{"http": 0, "https": 0, "socks5": 0, "socks5h": 0},
		UniqueExitCount:  admission.UniqueExitCount(),
		FailureClasses:   make(map[string]int),
		ValidatedAt:      admission.ValidatedAt,
	}
	for _, candidate := range admission.Candidates {
		status.AdmittedByScheme[candidate.Scheme]++
	}
	for _, failure := range admission.Failures {
		status.FailureClasses[failure.Code]++
	}
	return status
}

func (r *Router) probe(ctx context.Context, endpoint Endpoint) (Candidate, string) {
	parsed, err := parseEndpoint(endpoint.URL)
	if err != nil {
		return Candidate{}, "egress_endpoint_invalid"
	}
	client, err := r.clientForEndpoint(parsed)
	if err != nil {
		return Candidate{}, "proxy_transport_invalid"
	}
	defer client.CloseIdleConnections()
	if err := probeStatus(ctx, client, r.config.ReachabilityURL); err != nil {
		return Candidate{}, "proxy_platform_unreachable"
	}
	body, err := probeBody(ctx, client, r.config.IPEchoURL)
	if err != nil {
		return Candidate{}, "proxy_ip_echo_unreachable"
	}
	addr, err := NormalizePublicIP(body)
	if err != nil {
		return Candidate{}, ErrorCode(err)
	}
	return Candidate{ID: endpoint.ID, Scheme: parsed.scheme, Fingerprint: Fingerprint(r.config.HMACKey, r.config.HMACKeyVersion, addr), VerifiedAt: time.Now().UTC(), endpoint: endpoint}, ""
}

func probeStatus(ctx context.Context, client *http.Client, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, maxProbeBody)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.New("unreachable")
	}
	return nil
}

func probeBody(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	if err != nil || len(body) > maxProbeBody || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, errors.New("invalid echo")
	}
	return body, nil
}

// Snapshot of the IANA IPv4/IPv6 Special-Purpose Address Registries,
// plus multicast. Even globally reachable protocol assignments are not ordinary
// public exits and must not identify a platform account's egress route.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// NormalizePublicIP accepts only canonical public unicast addresses from the bounded echo body.
func NormalizePublicIP(raw []byte) (netip.Addr, error) {
	value := strings.TrimSpace(string(raw))
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, configError("proxy_ip_echo_invalid")
	}
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	if !addr.IsGlobalUnicast() || isNonPublic(addr) {
		return netip.Addr{}, configError("proxy_ip_echo_non_public")
	}
	return addr, nil
}

func isNonPublic(addr netip.Addr) bool {
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Fingerprint produces the only durable representation of a measured exit. The key version
// selects deployment key material; it is metadata and is not mixed into the stable message.
func Fingerprint(key []byte, _ string, addr netip.Addr) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fingerprintDomain))
	mac.Write([]byte(addr.String()))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// Client returns the dedicated direct transport. Required mode refuses this call by design.
func (r *Router) Client() (*http.Client, error) {
	if r.config.Mode == ModeRequired {
		return nil, configError("proxy_capacity_exhausted")
	}
	return r.clientForTransport(r.directTransport()), nil
}

// ClientFor reconstructs a transport only for the exact candidate admitted by the latest pass.
func (r *Router) ClientFor(candidate Candidate) (*http.Client, error) {
	if r.config.Mode != ModeRequired {
		return nil, configError("egress_direct_candidate_invalid")
	}
	r.mu.Lock()
	admitted, ok := r.candidates[string(candidate.Fingerprint[:])]
	r.mu.Unlock()
	if !ok || admitted.ID != candidate.ID || admitted.Scheme != candidate.Scheme {
		return nil, configError("proxy_candidate_not_admitted")
	}
	parsed, err := parseEndpoint(admitted.endpoint.URL)
	if err != nil {
		return nil, configError("proxy_candidate_not_admitted")
	}
	transport, err := r.transport(parsed)
	if err != nil {
		return nil, err
	}
	return r.clientForTransport(transport), nil
}

func (r *Router) clientForEndpoint(endpoint endpointURL) (*http.Client, error) {
	transport, err := r.transport(endpoint)
	if err != nil {
		return nil, err
	}
	return r.clientForTransport(transport), nil
}

func (r *Router) clientForTransport(transport *http.Transport) *http.Client {
	r.mu.Lock()
	r.transports[transport] = struct{}{}
	r.mu.Unlock()
	return &http.Client{Transport: transport, Timeout: r.config.RequestTimeout}
}

func (r *Router) directTransport() *http.Transport {
	tlsConfig := r.config.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: r.config.DialTimeout}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.TLSHandshake,
		ResponseHeaderTimeout: r.config.ResponseHeader,
		IdleConnTimeout:       r.config.IdleConn,
		ExpectContinueTimeout: time.Second,
	}
}

func (r *Router) transport(endpoint endpointURL) (*http.Transport, error) {
	transport := r.directTransport()
	switch endpoint.scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(endpoint.u)
		return transport, nil
	case "socks5", "socks5h":
		auth := (*proxy.Auth)(nil)
		if endpoint.hasAuth {
			auth = &proxy.Auth{User: endpoint.username, Password: endpoint.password}
		}
		dialer := &net.Dialer{Timeout: r.config.DialTimeout}
		socksDialer, err := proxy.SOCKS5("tcp", endpoint.u.Host, auth, dialer)
		if err != nil {
			return nil, configError("proxy_transport_invalid")
		}
		contextDialer, ok := socksDialer.(proxy.ContextDialer)
		if !ok {
			return nil, configError("proxy_transport_invalid")
		}
		transport.Proxy = nil
		if endpoint.scheme == "socks5" {
			transport.DialContext = r.localSOCKSDial(contextDialer)
		} else {
			transport.DialContext = contextDialer.DialContext
		}
		return transport, nil
	default:
		return nil, configError("egress_scheme_unsupported")
	}
}

func (r *Router) localSOCKSDial(dialer proxy.ContextDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return dialer.DialContext(ctx, network, address)
		}
		// socks5 resolves locally, while socks5h deliberately passes the hostname to
		// the proxy. Trying every local answer avoids treating IPv4/IPv6 ordering as
		// proxy capacity failure.
		ips, err := r.config.Resolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, configError("proxy_dns_failed")
		}
		var dialErr error
		for _, ip := range ips {
			var connection net.Conn
			connection, dialErr = dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if dialErr == nil {
				return connection, nil
			}
		}
		return nil, dialErr
	}
}

// CloseIdleConnections releases connection resources only. It does not release
// any task or egress lease; those belong to the workflow that owns the attempt.
func (r *Router) CloseIdleConnections() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for transport := range r.transports {
		transport.CloseIdleConnections()
		delete(r.transports, transport)
	}
}

// ParsePort accepts only explicit TCP ports in the IANA numeric range.
func ParsePort(raw string) bool {
	port, err := strconv.Atoi(raw)
	return err == nil && port > 0 && port <= 65535
}
