package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	// CSRFCookieName carries the browser half of the double-submit token.
	CSRFCookieName = "tsw_csrf"
	// CSRFHeaderName carries the application-readable half of the double-submit token.
	CSRFHeaderName = "X-CSRF-Token"
)

// OriginPolicy is an immutable exact-match allowlist built from deployment configuration.
type OriginPolicy struct {
	allowed map[string]struct{}
}

// ParseOriginPolicy validates a comma-separated list of absolute HTTP(S) origins.
func ParseOriginPolicy(value string) (OriginPolicy, error) {
	policy := OriginPolicy{allowed: make(map[string]struct{})}
	for _, raw := range strings.Split(value, ",") {
		origin := strings.TrimSpace(raw)
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return OriginPolicy{}, errors.New("invalid owner origin allowlist")
		}
		if _, exists := policy.allowed[origin]; exists {
			return OriginPolicy{}, errors.New("duplicate owner origin")
		}
		policy.allowed[origin] = struct{}{}
	}
	if len(policy.allowed) == 0 {
		return OriginPolicy{}, errors.New("owner origin allowlist is required")
	}
	return policy, nil
}

// Check rejects missing or unconfigured browser origins without consulting forwarding headers.
func (policy OriginPolicy) Check(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if _, ok := policy.allowed[origin]; !ok {
		return errors.New("origin not allowed")
	}
	return nil
}

// NewCSRFToken returns the current double-submit token or creates one for this browser session.
func NewCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	// Reusing a valid cookie prevents one Owner tab from invalidating another tab's in-memory token.
	if cookie, err := r.Cookie(CSRFCookieName); err == nil && validCSRFToken(cookie.Value) {
		return cookie.Value, nil
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/api/owner/v1",
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

// VerifyCSRF requires both the configured Origin and a constant-time double-submit match.
func VerifyCSRF(r *http.Request, policy OriginPolicy) error {
	if err := policy.Check(r); err != nil {
		return err
	}
	cookie, err := r.Cookie(CSRFCookieName)
	header := r.Header.Get(CSRFHeaderName)
	if err != nil || !validCSRFToken(cookie.Value) || !validCSRFToken(header) || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return errors.New("invalid CSRF token")
	}
	return nil
}

func validCSRFToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32
}
