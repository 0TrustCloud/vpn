// Package dbsc implements device-bound tunnel tickets (design KD5–KD9).
// Headless only: software Ed25519 or future TPM — no browser WebAuthn.
package dbsc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DeviceKey is a device-held key for tunnel binding (software Ed25519 in v0.1).
type DeviceKey struct {
	ID         string             `json:"id"`
	PrivateKey ed25519.PrivateKey `json:"-"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	Thumbprint string             `json:"thumbprint"`
	Security   string             `json:"security"` // software | hardware
	CreatedAt  time.Time          `json:"created_at"`
	privSeed   []byte
}

// Manager holds STEK + device registry for ticket mint/verify (server-side).
type Manager struct {
	mu      sync.Mutex
	stek    []byte
	devices map[string]*DeviceKey
	pubKeys map[string]ed25519.PublicKey
	tickets map[string]*Ticket
	hmacKey []byte
}

// Ticket is a multi-use resume ticket bound to a device thumbprint.
type Ticket struct {
	ID            string    `json:"ticket_id"`
	DeviceThumb   string    `json:"device_thumbprint"`
	Subject       string    `json:"subject"`
	TenantID      string    `json:"tenant_id"`
	ResumptionSec []byte    `json:"-"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ZeroRTTMode   string    `json:"zero_rtt_mode"` // safe | aggressive
}

// Proof is a device signature over a nonce (headless POP).
type Proof struct {
	DeviceThumb string `json:"device_thumbprint"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
	Timestamp   int64  `json:"ts"`
}

func NewManager(hmacKey []byte) *Manager {
	stek := make([]byte, 32)
	_, _ = rand.Read(stek)
	if len(hmacKey) == 0 {
		hmacKey = make([]byte, 32)
		_, _ = rand.Read(hmacKey)
	}
	return &Manager{
		stek:    stek,
		devices: make(map[string]*DeviceKey),
		pubKeys: make(map[string]ed25519.PublicKey),
		tickets: make(map[string]*Ticket),
		hmacKey: hmacKey,
	}
}

// GenerateSoftwareDevice creates a Mode-A software device key (no browser).
func GenerateSoftwareDevice() (*DeviceKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &DeviceKey{
		ID:         "dev_" + hex.EncodeToString(sum[:6]),
		PrivateKey: priv,
		PublicKey:  pub,
		Thumbprint: hex.EncodeToString(sum[:]),
		Security:   "software",
		CreatedAt:  time.Now().UTC(),
		privSeed:   priv.Seed(),
	}, nil
}

// LoadOrCreate loads a device key from path or creates one.
func LoadOrCreate(path string) (*DeviceKey, error) {
	if path == "" {
		return GenerateSoftwareDevice()
	}
	if d, err := LoadDevice(path); err == nil {
		return d, nil
	}
	d, err := GenerateSoftwareDevice()
	if err != nil {
		return nil, err
	}
	if err := d.Save(path); err != nil {
		return d, nil // still usable in-memory
	}
	return d, nil
}

func (d *DeviceKey) Save(path string) error {
	blob, err := json.Marshal(map[string]string{
		"id":         d.ID,
		"thumbprint": d.Thumbprint,
		"security":   d.Security,
		"seed_b64":   base64.StdEncoding.EncodeToString(d.privSeed),
		"created_at": d.CreatedAt.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

func LoadDevice(path string) (*DeviceKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(m["seed_b64"])
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &DeviceKey{
		ID:         m["id"],
		PrivateKey: priv,
		PublicKey:  pub,
		Thumbprint: m["thumbprint"],
		Security:   m["security"],
		privSeed:   seed,
	}, nil
}

func (m *Manager) RegisterDevice(thumb string, pub ed25519.PublicKey, security string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pubKeys[thumb] = pub
	m.devices[thumb] = &DeviceKey{Thumbprint: thumb, PublicKey: pub, Security: security}
}

func (d *DeviceKey) SignProof(nonce string) (*Proof, error) {
	ts := time.Now().Unix()
	msg := fmt.Sprintf("%s:%s:%d", d.Thumbprint, nonce, ts)
	sig := ed25519.Sign(d.PrivateKey, []byte(msg))
	return &Proof{
		DeviceThumb: d.Thumbprint,
		Nonce:       nonce,
		Signature:   base64.StdEncoding.EncodeToString(sig),
		Timestamp:   ts,
	}, nil
}

func (m *Manager) VerifyProof(p *Proof) error {
	if p == nil {
		return fmt.Errorf("dbsc: nil proof")
	}
	now := time.Now().Unix()
	if now-p.Timestamp > 300 || p.Timestamp-now > 120 {
		return fmt.Errorf("dbsc: proof expired")
	}
	m.mu.Lock()
	pub := m.pubKeys[p.DeviceThumb]
	m.mu.Unlock()
	if pub == nil {
		return fmt.Errorf("dbsc: unknown device")
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("%s:%s:%d", p.DeviceThumb, p.Nonce, p.Timestamp)
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return fmt.Errorf("dbsc: bad signature")
	}
	return nil
}

func (m *Manager) MintTicket(subject, tenant, deviceThumb, security string) (*Ticket, error) {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	mode := "safe"
	if security == "hardware" {
		mode = "aggressive"
	}
	t := &Ticket{
		ID:            hex.EncodeToString(id),
		DeviceThumb:   deviceThumb,
		Subject:       subject,
		TenantID:      tenant,
		ResumptionSec: sec,
		IssuedAt:      time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
		ZeroRTTMode:   mode,
	}
	m.mu.Lock()
	m.tickets[t.ID] = t
	m.mu.Unlock()
	return t, nil
}

// TicketJWT is a compact control-plane representation of the ticket.
func (m *Manager) TicketJWT(t *Ticket) (string, error) {
	claims := jwt.MapClaims{
		"tid":    t.ID,
		"sub":    t.Subject,
		"dth":    t.DeviceThumb,
		"tenant": t.TenantID,
		"zmode":  t.ZeroRTTMode,
		"iat":    t.IssuedAt.Unix(),
		"exp":    t.ExpiresAt.Unix(),
		"iss":    "0trust.vpn",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(m.hmacKey)
}

func (d *DeviceKey) PublicJSON() map[string]string {
	return map[string]string{
		"device_id":   d.ID,
		"thumbprint":  d.Thumbprint,
		"alg":         "Ed25519",
		"public_key":  base64.StdEncoding.EncodeToString(d.PublicKey),
		"security":    d.Security,
	}
}

func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dbsc: bad pubkey size")
	}
	return ed25519.PublicKey(b), nil
}

func Hash(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
