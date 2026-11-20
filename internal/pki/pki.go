// Package pki makes the certificates for mTLS between the asiri CLI and
// server: one Ed25519 CA per server, a server certificate, and a client
// certificate per paired profile.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CodePrefixLen is how many hex characters of the CA fingerprint a pairing
// code carries (64 bits), so the CLI can pin the CA before sending the code.
const CodePrefixLen = 16

// CA signs server and client certificates.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// NewCA makes a 10-year Ed25519 CA and returns it with its private key PEM.
func NewCA(now time.Time) (*CA, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "asiri CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := keyToPEM(priv)
	if err != nil {
		return nil, nil, err
	}
	ca, err := LoadCA(certToPEM(der), keyPEM)
	return ca, keyPEM, err
}

// LoadCA parses a CA certificate and its private key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Fingerprint is the CA's SHA-256 fingerprint, in hex.
func (ca *CA) Fingerprint() string { return Fingerprint(ca.Cert) }

// IssueServer makes a 5-year server certificate for hosts (names or IPs).
func (ca *CA) IssueServer(hosts []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "asiri server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = keyToPEM(priv)
	return certToPEM(der), keyPEM, err
}

// IssueClient signs a client certificate for csrPEM with common name cn.
// The CSR's own subject is ignored; the server decides the name.
func (ca *CA) IssueClient(csrPEM []byte, cn string, now time.Time) ([]byte, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return certToPEM(der), nil
}

// NewClientKey makes a client key and a CSR for it.
func NewClientKey() (keyPEM, csrPEM []byte, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "asiri client"}}, priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = keyToPEM(priv)
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), err
}

// Fingerprint is the SHA-256 of the certificate's DER, in hex.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func ParseCert(certPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func ParseKey(keyPEM []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(keyPEM)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key can't sign")
	}
	return s, nil
}

func certToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyToPEM(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
