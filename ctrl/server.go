package ctrl

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Server is a minimal lab control surface (token only).
// Prefer ProdServer for headless device DBSC + mesh PKI (still no browser).
type Server struct {
	Token        string
	TunnelHost   string // e.g. 127.0.0.1:51820 or us.vpn.0trust.services:51820
	PublicOrigin string // https://vpn.0trust.services
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /qd-ctrl/v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/tunnel/open", s.handleTunnelOpen)
	mux.HandleFunc("POST /qd-ctrl/v1/tunnel/open", s.handleTunnelOpen)
	mux.HandleFunc("GET /v1/regions", s.handleRegions)
	mux.HandleFunc("GET /qd-ctrl/v1/regions", s.handleRegions)
	return withHeaders(mux)
}

func withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status":   "ok",
		"service":  "0trust-vpn",
		"control":  "qd-ctrl/v1",
		"plane":    "0trust.services",
		"time":     time.Now().UTC().Format(time.RFC3339),
		"browser":  false,
		"note":     "lab token control — use -prod on qd-tunnel for client-local DBSC + mesh mTLS",
	})
}

func (s *Server) handleRegions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"regions": []map[string]any{
			{
				"id":       "lab",
				"hostname": s.TunnelHost,
				"endpoint": s.TunnelHost,
			},
		},
		"control": firstNonEmpty(s.PublicOrigin, "https://vpn.0trust.services"),
	})
}

func (s *Server) handleTunnelOpen(w http.ResponseWriter, r *http.Request) {
	// Lab auth: Bearer / enrollment token only (headless).
	auth := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(auth, "Bearer ")
	tok = strings.TrimSpace(tok)
	if tok == "" {
		tok = r.Header.Get("X-0Trust-VPN-Token")
	}
	if tok == "" {
		tok = r.Header.Get("X-0Trust-Enrollment-Token")
	}
	if s.Token != "" && tok != s.Token {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{
		"status":       "ok",
		"endpoint":     s.TunnelHost,
		"mode":         "split",
		"vip_pool":     "10.88.0.0/16",
		"tunnel_token": s.Token,
		"doh": map[string]any{
			"uri":        "https://10.88.0.1/dns-query",
			"shield":     "https://dns.0trust.services/dns-query",
			"use_tunnel": true,
			"secure_dns": true,
		},
		"protect_list": []string{
			"vpn.0trust.services",
			"0trust.cloud",
			"dns.0trust.services",
		},
		"transport": "qd-tun-dev/0.1",
		"browser":   false,
		"dbsc":      "optional_in_lab",
		"note":      "headless; client dials PoP; no browser",
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
