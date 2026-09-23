package publicaccess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// CookieName is the only browser transport for a customer access credential.
const CookieName = "tsw_redeem_access"

// NewToken creates a 256-bit opaque value and its only persisted representation.
func NewToken() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), sha256.Sum256(raw[:]), nil
}

// HashToken validates the exact 256-bit wire form before hashing it.
func HashToken(value string) ([32]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, errors.New("invalid customer access token")
	}
	return sha256.Sum256(decoded), nil
}

// Fingerprint returns a stable rate-limit input without retaining the raw token.
func Fingerprint(value string) [32]byte {
	if hash, err := HashToken(value); err == nil {
		return hash
	}
	return sha256.Sum256([]byte("teamseatwatch:public-token-input:v1\x00" + value))
}
