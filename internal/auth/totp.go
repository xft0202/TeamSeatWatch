package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NewTOTPSecret returns a 160-bit Base32 secret suitable for authenticator setup.
func NewTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// VerifyTOTP accepts the current 30-second value and one adjacent window for clock drift.
func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	if _, err := strconv.ParseUint(code, 10, 32); err != nil {
		return false
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(decoded) == 0 {
		return false
	}
	counter := now.Unix() / 30
	// Every candidate is compared in constant time; the small drift window is fixed policy.
	for offset := int64(-1); offset <= 1; offset++ {
		if counter+offset < 0 {
			continue
		}
		expected := totpCode(decoded, uint64(counter+offset))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCode(secret []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	hash := hmac.New(sha1.New, secret)
	_, _ = hash.Write(message[:])
	sum := hash.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := (uint32(sum[offset])&127)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}
