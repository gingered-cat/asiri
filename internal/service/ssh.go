package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gingered-cat/asiri/internal/audit"
	"github.com/gingered-cat/asiri/internal/domain"
)

// Signature flags from the SSH agent protocol.
const (
	FlagRSASHA256 = 2
	FlagRSASHA512 = 4
)

// sshPublicKey checks that value is an unencrypted SSH private key and
// returns its public key in authorized_keys form, with comment.
func sshPublicKey(value []byte, comment string) (string, error) {
	raw, err := ssh.ParseRawPrivateKey(value)
	var pm *ssh.PassphraseMissingError
	if errors.As(err, &pm) {
		return "", domain.Errorf(domain.CodeInvalid,
			"that SSH key has a passphrase; remove it for asiri (ssh-keygen -p -N '' -f KEY, on a copy) since asiri now protects it")
	}
	if err != nil {
		return "", domain.Errorf(domain.CodeInvalid, "not an SSH private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return "", domain.Errorf(domain.CodeInvalid, "unsupported SSH key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + comment, nil
}

// GenerateSSHKey makes a new Ed25519 key inside the server and stores it at
// ref. The private key never leaves the server; the item carries the public key.
func (s *Service) GenerateSSHKey(ctx context.Context, by domain.Client, ref domain.Ref) (domain.Item, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return domain.Item{}, err
	}
	block, err := ssh.MarshalPrivateKey(priv, ref.String())
	clear(priv)
	if err != nil {
		return domain.Item{}, err
	}
	sec := domain.NewSecret(pem.EncodeToMemory(block))
	clear(block.Bytes)
	defer sec.Zero()
	return s.PutItem(ctx, by, ref, domain.KindSSHKey, sec)
}

// SSHKeys lists the SSH keys, for the agent's identity list.
func (s *Service) SSHKeys(ctx context.Context) ([]domain.Item, error) {
	items, err := s.ListItems(ctx, "")
	if err != nil {
		return nil, err
	}
	out := []domain.Item{}
	for _, it := range items {
		if it.Kind == domain.KindSSHKey && it.PublicKey != "" {
			out = append(out, it)
		}
	}
	return out, nil
}

// SSHSign spends one use of an SSH grant and signs data with its key, here
// in the server.
func (s *Service) SSHSign(ctx context.Context, by domain.Client, gid domain.GrantID, data []byte, flags uint32) (*ssh.Signature, error) {
	g, err := s.spend(ctx, by, gid, true, audit.SSHSign, nil)
	if err != nil {
		return nil, err
	}
	_, sec, err := s.vault.GetByID(ctx, g.ItemID)
	if err != nil {
		return nil, err
	}
	defer sec.Zero()
	raw, err := ssh.ParseRawPrivateKey(sec.Reveal())
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, err
	}
	algo := ""
	switch {
	case flags&FlagRSASHA512 != 0:
		algo = ssh.KeyAlgoRSASHA512
	case flags&FlagRSASHA256 != 0:
		algo = ssh.KeyAlgoRSASHA256
	}
	if as, ok := signer.(ssh.AlgorithmSigner); ok && algo != "" && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		return as.SignWithAlgorithm(rand.Reader, data, algo)
	}
	return signer.Sign(rand.Reader, data)
}
