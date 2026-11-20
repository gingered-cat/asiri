package vault

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const keySize = chacha20poly1305.KeySize // 32

func randomKey() []byte {
	k := make([]byte, keySize)
	rand.Read(k)
	return k
}

// sealAEAD encrypts with XChaCha20-Poly1305 under a fresh random nonce.
func sealAEAD(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, a.NonceSize())
	rand.Read(nonce)
	return nonce, a.Seal(nil, nonce, plaintext, aad), nil
}

func openAEAD(key, nonce, ct, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}

func itemAAD(id string, version int, field string) []byte {
	return fmt.Appendf(nil, "asiri item v1|%s|%d|%s", id, version, field)
}

func dekAAD(id string, version int) []byte {
	return fmt.Appendf(nil, "asiri dek v1|%s|%d", id, version)
}

var vkAAD = []byte("asiri vk v1")

// KDF modes.
const (
	ModeKeyFile    = "keyfile"
	ModePassphrase = "passphrase"
)

// KDF says how the key-encryption key (KEK) is derived. It is stored in the
// database next to the wrapped vault key.
type KDF struct {
	Mode      string `json:"mode"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time,omitempty"`
	MemoryKiB uint32 `json:"memory_kib,omitempty"`
	Threads   uint8  `json:"threads,omitempty"`
}

// NewKDF returns production parameters with a fresh salt.
func NewKDF(mode string) KDF {
	salt := make([]byte, 16)
	rand.Read(salt)
	k := KDF{Mode: mode, Salt: salt}
	if mode == ModePassphrase {
		k.Time, k.MemoryKiB, k.Threads = 3, 256*1024, 4
	}
	return k
}

func (k KDF) deriveKEK(secret []byte) ([]byte, error) {
	switch k.Mode {
	case ModeKeyFile:
		if len(secret) != keySize {
			return nil, errors.New("key file must hold 32 bytes")
		}
		return hkdf.Key(sha256.New, secret, k.Salt, "asiri kek v1", keySize)
	case ModePassphrase:
		if len(secret) == 0 {
			return nil, errors.New("empty passphrase")
		}
		return argon2.IDKey(secret, k.Salt, k.Time, k.MemoryKiB, k.Threads, keySize), nil
	}
	return nil, fmt.Errorf("unknown kdf mode %q", k.Mode)
}

// NewKeyFile returns the text of a new key file: 32 random bytes, base64.
func NewKeyFile() []byte {
	return []byte(base64.StdEncoding.EncodeToString(randomKey()) + "\n")
}

// ReadKeyFile reads a key file written by NewKeyFile (or 32 raw bytes).
func ReadKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == keySize {
		return b, nil
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	clear(b)
	if err != nil || len(k) != keySize {
		return nil, fmt.Errorf("%s: not an asiri key file (want 32 bytes, base64)", path)
	}
	return k, nil
}
