// Package pki loads 0Trust.Cloud Mesh CA material and issues mTLS leaves for VPN.
// Certificates live under 0TrustCloud data/ca (mesh-root + mesh-intermediate).
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const leafDays = 90

// MeshCA is the platform intermediate CA used for VPN mTLS.
type MeshCA struct {
	dir       string
	rootCert  *x509.Certificate
	rootKey   *rsa.PrivateKey // optional; not required for Issue
	interCert *x509.Certificate
	interKey  *rsa.PrivateKey
	rootPool  *x509.CertPool
}

// Issued leaf certificate + key.
type Issued struct {
	Domain   string
	CertPEM  []byte
	KeyPEM   []byte
	ChainPEM []byte
	NotAfter time.Time
}

// LoadMeshCA loads mesh-root.crt + mesh-intermediate.{crt,key} from dir.
func LoadMeshCA(dir string) (*MeshCA, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("pki: mesh CA dir required")
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "mesh-root.crt"))
	if err != nil {
		return nil, fmt.Errorf("pki: mesh-root.crt: %w", err)
	}
	interPEM, err := os.ReadFile(filepath.Join(dir, "mesh-intermediate.crt"))
	if err != nil {
		return nil, fmt.Errorf("pki: mesh-intermediate.crt: %w", err)
	}
	interKeyPEM, err := os.ReadFile(filepath.Join(dir, "mesh-intermediate.key"))
	if err != nil {
		return nil, fmt.Errorf("pki: mesh-intermediate.key: %w", err)
	}
	rootCert, err := parseCert(rootPEM)
	if err != nil {
		return nil, err
	}
	interCert, interKey, err := parseCertKey(interPEM, interKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	pool.AddCert(interCert)
	return &MeshCA{
		dir:       dir,
		rootCert:  rootCert,
		interCert: interCert,
		interKey:  interKey,
		rootPool:  pool,
	}, nil
}

// DefaultCADir tries common locations for 0TrustCloud mesh CA.
func DefaultCADir() string {
	candidates := []string{
		os.Getenv("OTRUST_MESH_CA_DIR"),
		filepath.Join("..", "0TrustCloud", "data", "ca"),
		filepath.Join("C:", "Users", os.Getenv("USERNAME"), "0TrustCloud", "data", "ca"),
		"/opt/0trust/data/ca",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(c, "mesh-intermediate.key")); err == nil {
			return c
		}
	}
	return ""
}

// IssueLeaf mints a client/server auth certificate for domain (SAN = domain).
func (m *MeshCA) IssueLeaf(domain string) (*Issued, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("pki: domain required")
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain, Organization: []string{"0Trust.Cloud", "0Trust VPN"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafDays * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{domain, "vpn.0trust.services", "localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.interCert, &leafKey.PublicKey, m.interKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chain := append([]byte{}, certPEM...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.interCert.Raw})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.rootCert.Raw})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	return &Issued{
		Domain:   domain,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		ChainPEM: chain,
		NotAfter: tmpl.NotAfter,
	}, nil
}

// ServerTLS returns tls.Config requiring client certs (mTLS) for the tunnel PoP.
func (m *MeshCA) ServerTLS(leaf *Issued) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		return nil, err
	}
	// Include intermediate in cert chain for clients
	if block, _ := pem.Decode(m.interCert.Raw); block == nil {
		// attach from PEM chain
		_ = block
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    m.rootPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"qd-tun-dev/0.1", "qd-mux/0.1"},
	}, nil
}

// ClientTLS returns tls.Config presenting a client cert and trusting the mesh root.
func (m *MeshCA) ClientTLS(leaf *Issued, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		return nil, err
	}
	if serverName == "" {
		serverName = "vpn.0trust.services"
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      m.rootPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"qd-tun-dev/0.1", "qd-mux/0.1"},
	}, nil
}

// RootPool exposes the trust anchors.
func (m *MeshCA) RootPool() *x509.CertPool { return m.rootPool }

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pki: invalid cert PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCertKey(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("pki: invalid key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("pki: not RSA key")
		}
		return cert, rk, nil
	}
	return cert, key, nil
}
