package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
)

const cardPrefix = "TSW1-"

var ErrInvalidCard = errors.New("card secret is invalid")

// ValidateCardSecret accepts only the browser-generated 160-bit TSW1 format.
// The control service never generates or persists this value.
func ValidateCardSecret(secret string) error {
	if !strings.HasPrefix(secret, cardPrefix) {
		return ErrInvalidCard
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(secret, cardPrefix))
	if err != nil || len(raw) != 20 {
		return ErrInvalidCard
	}
	return nil
}

// LookupHMAC derives the versioned, domain-separated lookup value persisted by
// the control service. The original card secret is intentionally not recoverable.
func LookupHMAC(ring auth.KeyRing, secret string) (uint16, [sha256.Size]byte, error) {
	if ring == nil || ValidateCardSecret(secret) != nil {
		return 0, [sha256.Size]byte{}, ErrInvalidCard
	}
	version, _ := ring.Current()
	result, err := LookupHMACVersion(ring, version, secret)
	return version, result, err
}

// LookupHMACVersion derives a lookup value with the key version stored by an
// existing card. This lets key rotation preserve cards until their retention
// period ends without trying every deployment key outside the control service.
func LookupHMACVersion(ring auth.KeyRing, version uint16, secret string) ([sha256.Size]byte, error) {
	if ring == nil || ValidateCardSecret(secret) != nil {
		return [sha256.Size]byte{}, ErrInvalidCard
	}
	key, ok := ring.Lookup(version)
	if !ok {
		return [sha256.Size]byte{}, ErrInvalidCard
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("teamseatwatch:card:v1\x00"))
	_, _ = mac.Write([]byte(secret))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func DisplaySuffix(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 8 {
		return secret
	}
	return secret[len(secret)-8:]
}
