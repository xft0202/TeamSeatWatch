package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
)

// Kind separates identifiers that must not be linkable across persistence domains.
type Kind string

const (
	MotherLogin    Kind = "mother-login"
	WorkspaceEntry Kind = "workspace-entry"
)

// Fingerprint normalizes a platform identifier and protects it with the current
// deployment key version. The purpose label prevents cross-table correlation.
func Fingerprint(keyRing auth.KeyRing, kind Kind, value string) (string, uint16, [sha256.Size]byte, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if keyRing == nil || normalized == "" || (kind != MotherLogin && kind != WorkspaceEntry) {
		return "", 0, [sha256.Size]byte{}, errors.New("identifier fingerprint input is invalid")
	}
	version, key := keyRing.Current()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("teamseatwatch:identifier:v1\x00"))
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(normalized))
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], mac.Sum(nil))
	return normalized, version, fingerprint, nil
}
