package oauth

import (
	"testing"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
)

type testKeyRing struct{ key [32]byte }

func (r testKeyRing) Current() (uint16, [32]byte)            { return 7, r.key }
func (r testKeyRing) Lookup(version uint16) ([32]byte, bool) { return r.key, version == 7 }

func TestCardSecretValidationAndLookupHMAC(t *testing.T) {
	secret := "TSW1-AAAAAAAAAAAAAAAAAAAAAAAAAAA" // 20 raw bytes in base64url form
	if err := ValidateCardSecret(secret); err != nil {
		t.Fatalf("valid card rejected: %v", err)
	}
	version, first, err := LookupHMAC(testKeyRing{}, secret)
	if err != nil || version != 7 {
		t.Fatalf("lookup hmac failed: version=%d err=%v", version, err)
	}
	_, second, err := LookupHMAC(testKeyRing{}, "TSW1-BBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if err != nil || first == second {
		t.Fatal("different card secrets must not share a lookup hmac")
	}
	if DisplaySuffix(secret) != secret[len(secret)-8:] {
		t.Fatal("display suffix must be a bounded non-secret projection")
	}
}

func TestCardSecretRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "TSW2-AAAAAAAAAAAAAAAAAAAAAAAAAAA", "TSW1-%%%", "TSW1-AAAA"} {
		if ValidateCardSecret(value) == nil {
			t.Fatalf("malformed card accepted: %q", value)
		}
	}
}

var _ auth.KeyRing = testKeyRing{}
