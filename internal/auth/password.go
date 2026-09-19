package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// PasswordMinLength is the product policy measured in Unicode code points.
const PasswordMinLength = 14

const (
	argonVersion    uint32 = 19
	argonMemory     uint32 = 65536
	argonTime       uint32 = 3
	argonThreads    uint8  = 4
	argonSaltLength        = 16
	argonKeyLength         = 32
)

// HashPassword validates policy and returns a versioned Argon2id PHC-style value with a fresh salt.
func HashPassword(password string) (string, error) {
	if utf8.RuneCountInString(password) < PasswordMinLength {
		return "", errors.New("password is too short")
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	// Fixed, named parameters keep verification deterministic and meet the approved OWASP baseline.
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	enc := base64.RawURLEncoding
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argonVersion, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(hash)), nil
}

// VerifyPassword rejects unknown parameter sets and compares the derived key in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" || parts[2] != "m=65536,t=3,p=4" {
		return false
	}
	enc := base64.RawURLEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil || len(salt) != argonSaltLength {
		return false
	}
	expected, err := enc.DecodeString(parts[4])
	if err != nil || len(expected) != argonKeyLength {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
