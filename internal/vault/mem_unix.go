//go:build unix

package vault

import "golang.org/x/sys/unix"

// lockMemory keeps b out of swap. Best effort: containers without
// CAP_IPC_LOCK or a low RLIMIT_MEMLOCK may refuse, and that is not fatal.
func lockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Mlock(b)
	}
}

func unlockMemory(b []byte) {
	if len(b) > 0 {
		_ = unix.Munlock(b)
	}
}
