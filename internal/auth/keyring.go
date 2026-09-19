package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// KeyRing resolves versioned, deployment-held AES keys without exposing storage details.
type KeyRing interface {
	Current() (version uint16, key [32]byte)
	Lookup(version uint16) ([32]byte, bool)
}

type keyRing struct {
	current uint16
	keys    map[uint16][32]byte
}

func (r keyRing) Current() (uint16, [32]byte)            { return r.current, r.keys[r.current] }
func (r keyRing) Lookup(version uint16) ([32]byte, bool) { key, ok := r.keys[version]; return key, ok }

// LoadKeyRingFile parses a strict keyring document and requires the current key to exist.
func LoadKeyRingFile(path string) (KeyRing, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read TOTP key ring")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid TOTP key ring")
	}
	var current uint16
	var keys map[uint16][32]byte
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid TOTP key ring")
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return nil, errors.New("invalid TOTP key ring")
		}
		seen[name] = true
		switch name {
		case "current_version":
			if err := decoder.Decode(&current); err != nil {
				return nil, errors.New("invalid TOTP key ring")
			}
		case "keys":
			var err error
			keys, err = decodeKeys(decoder)
			if err != nil {
				return nil, errors.New("invalid TOTP key ring")
			}
		default:
			return nil, errors.New("invalid TOTP key ring")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid TOTP key ring")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF || current == 0 || len(keys) == 0 {
		return nil, errors.New("invalid TOTP key ring")
	}
	if _, ok := keys[current]; !ok || current > 32767 {
		return nil, errors.New("invalid TOTP key ring")
	}
	return keyRing{current: current, keys: keys}, nil
}

func decodeKeys(decoder *json.Decoder) (map[uint16][32]byte, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid key map")
	}
	keys := make(map[uint16][32]byte)
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return nil, errors.New("invalid key map")
		}
		seen[name] = true
		var version uint16
		if _, err := fmt.Sscanf(name, "%d", &version); err != nil || version == 0 || version > 32767 || fmt.Sprintf("%d", version) != name {
			return nil, errors.New("invalid key map")
		}
		var encoded string
		if err := decoder.Decode(&encoded); err != nil {
			return nil, errors.New("invalid key map")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != 32 {
			return nil, errors.New("invalid key map")
		}
		var key [32]byte
		copy(key[:], decoded)
		keys[version] = key
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(keys) == 0 {
		return nil, errors.New("invalid key map")
	}
	return keys, nil
}

// EncryptTOTP seals a TOTP secret with the current versioned deployment key and a fresh nonce.
func EncryptTOTP(secret []byte, ring KeyRing) (version uint16, nonce, ciphertext []byte, err error) {
	version, key := ring.Current()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return 0, nil, nil, errors.New("initialize TOTP encryption")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, nil, errors.New("initialize TOTP encryption")
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, nil, nil, errors.New("generate TOTP nonce")
	}
	// AES-GCM authenticates both the ciphertext and nonce before a secret is used.
	return version, nonce, gcm.Seal(nil, nonce, secret, nil), nil
}

// DecryptTOTP authenticates ciphertext with the key version stored alongside it.
func DecryptTOTP(version uint16, nonce, ciphertext []byte, ring KeyRing) ([]byte, error) {
	key, ok := ring.Lookup(version)
	if !ok {
		return nil, errors.New("TOTP key version unavailable")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, errors.New("initialize TOTP decryption")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid TOTP ciphertext")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("invalid TOTP ciphertext")
	}
	return plaintext, nil
}
