package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"time"
)

const (
	// SessionIdleTimeout is extended on authenticated activity but never beyond the absolute deadline.
	SessionIdleTimeout = 8 * time.Hour
	// SessionAbsoluteTimeout bounds a session regardless of activity.
	SessionAbsoluteTimeout = 24 * time.Hour
	// SessionCookieName is the host-only Owner session cookie name.
	SessionCookieName = "tsw_session"
)

// NewSessionToken returns a 256-bit bearer token and the only representation stored in PostgreSQL.
func NewSessionToken() (token string, hash [32]byte, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", hash, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw[:])
	hash = sha256.Sum256(raw[:])
	return token, hash, nil
}

// HashSessionToken validates the encoded token before deriving its database lookup hash.
func HashSessionToken(token string) ([32]byte, error) {
	var empty [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return empty, errors.New("invalid session token")
	}
	return sha256.Sum256(raw), nil
}

// SetSessionCookie writes a strict transport cookie that expires at the database-approved idle deadline.
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
		MaxAge:   maxAge,
	})
}

// ClearSessionCookie removes the browser credential after revocation or local expiry.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// NewRecoveryCode returns 192 bits of entropy and its one-way database representation.
func NewRecoveryCode() (display string, hash [32]byte, err error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", hash, err
	}
	display = base64.RawURLEncoding.EncodeToString(raw[:])
	hash = sha256.Sum256([]byte(display))
	return display, hash, nil
}

// HashRecoveryCode derives the lookup value for an Owner-supplied one-time code.
func HashRecoveryCode(display string) [32]byte {
	return sha256.Sum256([]byte(display))
}

// SourceFingerprint produces a non-reversible audit correlation value without trusting forwarding headers.
func SourceFingerprint(remoteAddress, userAgent string) [32]byte {
	host := remoteAddress
	if parsed, _, err := net.SplitHostPort(remoteAddress); err == nil {
		host = parsed
	}
	return sha256.Sum256([]byte("teamseatwatch:owner-source:v1\x00" + host + "\x00" + userAgent))
}
