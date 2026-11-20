package vault

import (
	"sync"

	"github.com/gingered-cat/asiri/internal/domain"
)

// ErrSealed is returned by anything that needs the vault key while it is locked.
var ErrSealed = domain.Errorf(domain.CodeSealed, "the vault is locked; run `asiri unlock`")

// keyring holds the vault key in locked memory. Readers decrypt concurrently;
// sealing and unsealing take the write lock and wipe the old key.
type keyring struct {
	mu sync.RWMutex
	vk []byte
}

func (k *keyring) sealed() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.vk == nil
}

// unseal takes ownership of vk.
func (k *keyring) unseal(vk []byte) {
	lockMemory(vk)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wipe()
	k.vk = vk
}

func (k *keyring) seal() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wipe()
}

func (k *keyring) wipe() {
	if k.vk != nil {
		clear(k.vk)
		unlockMemory(k.vk)
		k.vk = nil
	}
}

// with runs fn with the vault key, or returns ErrSealed. fn must not keep vk.
func (k *keyring) with(fn func(vk []byte) error) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.vk == nil {
		return ErrSealed
	}
	return fn(k.vk)
}
