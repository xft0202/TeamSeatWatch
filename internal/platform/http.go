package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const maxResponseBody = 1 << 20

type Credentials struct {
	LoginIdentifier string
	Password        string
}

type HTTPConfig struct {
	baseURL *url.URL
}

type HTTPReader struct {
	client      *http.Client
	config      HTTPConfig
	credentials Credentials
}

// NewHTTPConfig validates immutable deployment inputs without constructing an
// alternate client that could bypass the egress lease boundary.
func NewHTTPConfig(baseURL string) (HTTPConfig, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || base.User != nil || !securePlatformURL(base) {
		return HTTPConfig{}, errors.New("platform reader configuration is invalid")
	}
	return HTTPConfig{baseURL: base}, nil
}

func securePlatformURL(base *url.URL) bool {
	if base.Scheme == "https" {
		return true
	}
	if base.Scheme != "http" {
		return false
	}
	host := strings.ToLower(base.Hostname())
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// Reader binds validated configuration to the lease-owned client used by this attempt.
func (c HTTPConfig) Reader(client *http.Client, credentials Credentials) (*HTTPReader, error) {
	if client == nil || client.Timeout <= 0 || client.Transport == nil ||
		credentials.LoginIdentifier == "" || credentials.Password == "" {
		return nil, errors.New("platform reader client is invalid")
	}
	return &HTTPReader{client: client, config: c, credentials: credentials}, nil
}

// NewHTTPReader is the direct constructor used by focused fixtures.
func NewHTTPReader(client *http.Client, baseURL string, credentials Credentials) (*HTTPReader, error) {
	config, err := NewHTTPConfig(baseURL)
	if err != nil {
		return nil, err
	}
	return config.Reader(client, credentials)
}

func (r *HTTPReader) ReadExchange(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointExchange)
}
func (r *HTTPReader) ReadSubscription(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointSubscription)
}
func (r *HTTPReader) ReadCapacity(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointCapacity)
}
func (r *HTTPReader) ReadJoin(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointJoin)
}
func (r *HTTPReader) ReadMembers(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointMembers)
}
func (r *HTTPReader) ReadPendingInvites(ctx context.Context, workspace string) (Result, error) {
	return r.read(ctx, workspace, EndpointPendingInvite)
}

type wireResponse struct {
	ErrorCode          string     `json:"error_code"`
	ActiveUntil        *time.Time `json:"active_until"`
	SeatLimit          *int       `json:"seat_limit"`
	MemberCount        *int       `json:"member_count"`
	PendingInviteCount *int       `json:"pending_invite_count"`
	Complete           *bool      `json:"complete"`
	Members            []Member   `json:"members"`
}

func (r *HTTPReader) read(ctx context.Context, workspace string, endpoint Endpoint) (Result, error) {
	result := Result{Endpoint: endpoint, ObservedAt: time.Now().UTC(), Completeness: Unknown}
	path := fmt.Sprintf("/workspaces/%s/%s", url.PathEscape(workspace), endpoint)
	target := r.config.baseURL.ResolveReference(&url.URL{Path: strings.TrimSuffix(r.config.baseURL.Path, "/") + path})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return result, errors.New("platform request invalid")
	}
	req.SetBasicAuth(r.credentials.LoginIdentifier, r.credentials.Password)
	req.Header.Set("Accept", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		result.Outcome = Classify(0, "", err)
		return result, err
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil || len(body) > maxResponseBody {
		result.Outcome = OutcomeIncomplete
		return result, nil
	}
	var wire wireResponse
	if len(body) == 0 || json.Unmarshal(body, &wire) != nil {
		result.Outcome = OutcomeIncomplete
		return result, nil
	}
	result.Outcome = Classify(response.StatusCode, wire.ErrorCode, nil)
	if result.Outcome == OutcomeOperational &&
		((endpoint == EndpointSubscription && wire.ActiveUntil == nil) ||
			(endpoint == EndpointCapacity && (wire.SeatLimit == nil || wire.MemberCount == nil)) ||
			(endpoint == EndpointPendingInvite && wire.PendingInviteCount == nil) ||
			(endpoint == EndpointMembers && wire.Complete == nil)) {
		result.Outcome = OutcomeIncomplete
	}
	result.ActiveUntil = wire.ActiveUntil
	result.SeatLimit = wire.SeatLimit
	result.MemberCount = wire.MemberCount
	result.PendingInviteCount = wire.PendingInviteCount
	result.Members = wire.Members
	if wire.Complete != nil {
		if *wire.Complete {
			result.Completeness = Complete
		} else {
			result.Completeness = Partial
		}
	}
	if endpoint == EndpointMembers {
		members, valid := validMembers(wire.Members)
		result.Members = members
		if !valid {
			result.Outcome = OutcomeIncomplete
			result.Completeness = Partial
		}
	}
	if endpoint == EndpointMembers && result.Outcome == OutcomeOperational && wire.Complete == nil {
		result.Outcome = OutcomeIncomplete
	}
	if result.Outcome != OutcomeOperational && endpoint != EndpointMembers {
		result.ActiveUntil = nil
		result.SeatLimit = nil
		result.MemberCount = nil
		result.PendingInviteCount = nil
	}
	return result, nil
}

func validMembers(members []Member) ([]Member, bool) {
	valid := make([]Member, 0, len(members))
	complete := true
	for _, member := range members {
		identifierLength, statusLength, roleLength := utf8.RuneCountInString(member.Identifier), utf8.RuneCountInString(member.Status), utf8.RuneCountInString(member.Role)
		shapeValid := (member.Kind == "member" && member.PlatformMemberID != "") ||
			(member.Kind == "pending_invite" && member.PlatformMemberID == "")
		if !shapeValid || identifierLength < 1 || identifierLength > 254 || statusLength < 1 || statusLength > 64 || roleLength > 64 {
			complete = false
			continue
		}
		valid = append(valid, member)
	}
	return valid, complete
}
