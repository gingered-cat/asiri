//go:build !unix

package vault

func lockMemory([]byte)   {}
func unlockMemory([]byte) {}
