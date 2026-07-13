package ctrl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/vpn/dbsc"
	"github.com/0TrustCloud/vpn/doh"
	"github.com/0TrustCloud/vpn/pki"
)

// ProdConfig is headless control for 0Trust VPN.
//
// All device binding is client-local DBSC (keys live in the VPN client process/files).
// No browser WebAuthn / interactive OIDC is used for tunnel open.
//
// Auth (headless only):
//  1. Enrollment / service token (pre-shared, machine-provisioned)
//  2. Client-held device key proof (Ed25519; future TPM inside same client)
//  3. Optional mesh mTLS leaf issued to the client for the data plane
type ProdConfig struct {
	EnrollmentToken    string
	TunnelToken        string
	TunnelHost         string
	PublicOrigin       string
	MeshCA             *pki.MeshCA
	DBSC               *dbsc.Manager
	RequireDeviceProof bool
	// AdminRoutes CIDRs/host routes for admin clients (droplets over VPN).
	AdminRoutes []string
	// Role label returned on open (e.g. admin).
	Role string
}

// ProdServer implements qd-ctrl/v1 for headless clients.
type ProdServer struct {
	Cfg    ProdConfig
	mu     sync.Mutex
	nonces map[string]int64
}

func NewProd(cfg ProdConfig) *ProdServer {
	if cfg.DBSC == nil {
		cfg.DBSC = dbsc.NewManager(nil)
	}
	if cfg.PublicOrigin == "" {
		cfg.PublicOrigin = "https://mesh-vpn.0trust.services"
	}
	if cfg.Role == "" {
		cfg.Role = "admin"
	}
	return &ProdServer{Cfg: cfg, nonces: make(map[string]int64)}
}

func (s *ProdServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /qd-ctrl/v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/regions", s.handleRegions)
	mux.HandleFunc("GET /qd-ctrl/v1/regions", s.handleRegions)
	mux.HandleFunc("POST /v1/device/register", s.handleDeviceRegister)
	mux.HandleFunc("POST /qd-ctrl/v1/device/register", s.handleDeviceRegister)
	mux.HandleFunc("POST /v1/device/cert", s.handleDeviceCert)
	mux.HandleFunc("POST /qd-ctrl/v1/device/cert", s.handleDeviceCert)
	mux.HandleFunc("GET /v1/device/nonce", s.handleNonce)
	mux.HandleFunc("GET /qd-ctrl/v1/device/nonce", s.handleNonce)
	mux.HandleFunc("POST /v1/tunnel/open", s.handleTunnelOpen)
	mux.HandleFunc("POST /qd-ctrl/v1/tunnel/open", s.handleTunnelOpen)
	// Lab-compatible path used by earlier client
	mux.HandleFunc("POST /v1/tunnel/open/", s.handleTunnelOpen)
	return withHeaders(mux)
}

func (s *ProdServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status":        "ok",
		"service":       "0trust-vpn",
		"control":       "qd-ctrl/v1",
		"plane":         "0trust.services",
		"endpoint":      "mesh-vpn.0trust.services",
		"browser":       false,
		"dbsc":          "client_local",
		"auth":          []string{"enrollment_token", "client_device_dbsc", "mesh_mtls"},
		"webauthn":      "not_used_in_vpn_client",
		"pki":           s.Cfg.MeshCA != nil,
		"doh":           doh.DefaultPublicDoH,
		"role":          s.Cfg.Role,
		"routes":        s.Cfg.AdminRoutes,
		"port_punch":    false,
		"stun":          false,
		"turn":          false,
		"nat_traversal": false,
		"dial_only":     true,
		"note":          "admin mesh VPN on mesh-vpn.0trust.services; dial-only; droplet routes on open",
		"time":          time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *ProdServer) handleRegions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"regions": []map[string]any{{
			"id": "default", "hostname": s.Cfg.TunnelHost, "endpoint": s.Cfg.TunnelHost,
		}},
		"control": s.Cfg.PublicOrigin,
		"routes":  s.Cfg.AdminRoutes,
	})
}

func (s *ProdServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	var b [16]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.nonces[nonce] = time.Now().Add(5 * time.Minute).Unix()
	s.mu.Unlock()
	writeJSON(w, map[string]string{"nonce": nonce})
}

type deviceRegisterReq struct {
	EnrollmentToken string `json:"enrollment_token"`
	DeviceID        string `json:"device_id"`
	Thumbprint      string `json:"thumbprint"`
	PublicKey       string `json:"public_key"`
	Security        string `json:"security"`
	Subject         string `json:"subject"`
	TenantID        string `json:"tenant_id"`
}

func (s *ProdServer) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req deviceRegisterReq
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if !s.enrollOK(req.EnrollmentToken, r) {
		http.Error(w, `{"error":"enrollment_required"}`, http.StatusUnauthorized)
		return
	}
	pub, err := dbsc.ParsePublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, `{"error":"bad public_key"}`, http.StatusBadRequest)
		return
	}
	thumb := req.Thumbprint
	if thumb == "" {
		thumb = dbsc.Hash(pub)
	}
	sec := req.Security
	if sec == "" {
		sec = "software"
	}
	s.Cfg.DBSC.RegisterDevice(thumb, ed25519.PublicKey(pub), sec)
	log.Printf("[qd-ctrl] client device registered thumb=%s… subject=%s (headless)", short(thumb), req.Subject)
	writeJSON(w, map[string]any{
		"status": "ok", "thumbprint": thumb, "device_id": req.DeviceID, "security": sec,
	})
}

type deviceCertReq struct {
	EnrollmentToken string `json:"enrollment_token"`
	Domain          string `json:"domain"`
	Thumbprint      string `json:"thumbprint"`
}

func (s *ProdServer) handleDeviceCert(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.MeshCA == nil {
		http.Error(w, `{"error":"mesh_ca_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req deviceCertReq
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if !s.enrollOK(req.EnrollmentToken, r) {
		http.Error(w, `{"error":"enrollment_required"}`, http.StatusUnauthorized)
		return
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = "client.vpn.0trust.services"
	}
	issued, err := s.Cfg.MeshCA.IssueLeaf(domain)
	if err != nil {
		http.Error(w, `{"error":"issue_failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"status":    "ok",
		"domain":    issued.Domain,
		"cert_pem":  string(issued.CertPEM),
		"key_pem":   string(issued.KeyPEM),
		"chain_pem": string(issued.ChainPEM),
		"not_after": issued.NotAfter,
		"pki":       "0trust.cloud mesh CA",
	})
}

type tunnelOpenReq struct {
	EnrollmentToken string      `json:"enrollment_token"`
	Subject         string      `json:"subject"`
	TenantID        string      `json:"tenant_id"`
	DeviceThumb     string      `json:"device_thumbprint"`
	Proof           *dbsc.Proof `json:"proof"`
	Mode            string      `json:"mode"`
}

func (s *ProdServer) handleTunnelOpen(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req tunnelOpenReq
	_ = json.Unmarshal(body, &req)

	// Prefer client-local device proof when present; enrollment token still required for bootstrap.
	if !s.enrollOK(req.EnrollmentToken, r) {
		http.Error(w, `{"error":"enrollment_required"}`, http.StatusUnauthorized)
		return
	}
	if s.Cfg.RequireDeviceProof || req.Proof != nil {
		if req.Proof == nil {
			http.Error(w, `{"error":"device_proof_required"}`, http.StatusUnauthorized)
			return
		}
		if err := s.Cfg.DBSC.VerifyProof(req.Proof); err != nil {
			http.Error(w, `{"error":"invalid_device_proof"}`, http.StatusUnauthorized)
			return
		}
	}

	subject := req.Subject
	if subject == "" && req.DeviceThumb != "" {
		subject = "device:" + req.DeviceThumb[:min(12, len(req.DeviceThumb))]
	}
	if subject == "" {
		subject = "vpn-client"
	}
	tenant := req.TenantID
	if tenant == "" {
		tenant = "default"
	}
	ticket, err := s.Cfg.DBSC.MintTicket(subject, tenant, req.DeviceThumb, "software")
	if err != nil {
		http.Error(w, `{"error":"ticket_mint_failed"}`, http.StatusInternalServerError)
		return
	}
	tjwt, _ := s.Cfg.DBSC.TicketJWT(ticket)
	snap := doh.DefaultSnapshot("")
	mode := req.Mode
	if mode == "" {
		mode = "split"
	}

	routes := s.Cfg.AdminRoutes
	if routes == nil {
		routes = []string{}
	}
	writeJSON(w, map[string]any{
		"status":       "ok",
		"endpoint":     s.Cfg.TunnelHost,
		"mode":         mode,
		"vip_pool":     "10.88.0.0/16",
		"tunnel_token": s.Cfg.TunnelToken,
		"ticket_id":    ticket.ID,
		"ticket_jwt":   tjwt,
		"zero_rtt":     ticket.ZeroRTTMode,
		"subject":      subject,
		"tenant_id":    tenant,
		"role":         s.Cfg.Role,
		// Admin host routes: each droplet /32 + VIP pool (client installs as split routes).
		"routes": routes,
		"doh": map[string]any{
			"uri":        snap.DoHURI,
			"use_tunnel": snap.UseTunnel,
			"bootstrap":  doh.DefaultPublicDoH,
			"gtld":       doh.DefaultPublicDoH,
			"shield":     doh.DefaultShieldDoH,
			"cloud":      doh.DefaultCloudDoH,
			"secure_dns": true,
		},
		"protect_list": snap.ProtectList,
		"transport":    "qd-tun-dev/0.1+mtls",
		"browser":      false,
		"dbsc":         "client_local",
		"note":         "admin mesh-vpn.0trust.services: local device key + enrollment; routes to droplets",
	})
}

func (s *ProdServer) enrollOK(token string, r *http.Request) bool {
	want := strings.TrimSpace(s.Cfg.EnrollmentToken)
	if want == "" {
		want = strings.TrimSpace(s.Cfg.TunnelToken)
	}
	if want == "" {
		return false
	}
	got := strings.TrimSpace(token)
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got = strings.TrimSpace(got)
	}
	if got == "" {
		got = r.Header.Get("X-0Trust-Enrollment-Token")
	}
	return got != "" && got == want
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
