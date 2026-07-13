// Package doh talks to 0Trust secure_dns-compatible RFC 8484 endpoints.
// Bootstrap / public preferred DoH is the gTLD face: https://dns.0trust.name/dns-query
// Steady-state DoH is vpn-side VIP when the tunnel is up.
// Headless: optional Bearer session cookie/token, never a browser.
package doh

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Default endpoints — preferred public DoH is the 0trust.name gTLD face.
const (
	// DefaultPublicDoH is the canonical bootstrap DoH (gTLD server face).
	DefaultPublicDoH = "https://dns.0trust.name/dns-query"
	// DefaultGTLDDoH alias of DefaultPublicDoH.
	DefaultGTLDDoH = DefaultPublicDoH
	// DefaultShieldDoH is privacy DoH on the services edge (DBSC-gated).
	DefaultShieldDoH = "https://dns.0trust.services/dns-query"
	// DefaultCloudDoH is the control-plane DoH alias.
	DefaultCloudDoH = "https://dns.0trust.cloud/dns-query"
	// Tunnel VIP DoH when full/split tunnel is up (design default).
	DefaultTunnelDoHVIP = "https://10.88.0.1/dns-query"
)

// Client is a headless DoH resolver.
type Client struct {
	// Endpoint e.g. https://dns.0trust.name/dns-query
	Endpoint string
	// Bearer optional session_id / access token for DBSC-gated Shield.
	Bearer string
	// HTTPClient optional.
	HTTPClient *http.Client
	// InsecureSkipVerify only for lab.
	InsecureSkipVerify bool
}

// ConfigSnapshot is returned from control open for client protect-list + DNS.
type ConfigSnapshot struct {
	DoHURI       string   `json:"doh_uri"`
	UseTunnel    bool     `json:"use_tunnel"`
	BootstrapIPs []string `json:"doh_bootstrap_ips,omitempty"`
	ProtectList  []string `json:"protect_list"`
}

// DefaultProtectList excludes control/IdP/DoH from full-tunnel black-hole (KD32).
func DefaultProtectList() []string {
	return []string{
		"mesh-vpn.0trust.services",
		"vpn.0trust.services",
		"0trust.cloud",
		"dns.0trust.cloud",
		"dns.0trust.name",
		"0trust.name",
		"dns.0trust.services",
		"0trust.services",
	}
}

// DefaultSnapshot for tunnel open responses.
func DefaultSnapshot(tunnelDoH string) ConfigSnapshot {
	if tunnelDoH == "" {
		tunnelDoH = DefaultTunnelDoHVIP
	}
	return ConfigSnapshot{
		DoHURI:      tunnelDoH,
		UseTunnel:   true,
		ProtectList: DefaultProtectList(),
	}
}

// ResolveA resolves name to IPv4 via DoH (minimal A query wire format).
func (c *Client) ResolveA(ctx context.Context, name string) (net.IP, error) {
	endpoint := strings.TrimSpace(c.Endpoint)
	if endpoint == "" {
		endpoint = DefaultPublicDoH
	}
	wire := buildQueryA(name)
	q := base64.RawURLEncoding.EncodeToString(wire)
	url := endpoint + "?dns=" + q

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 8 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh: HTTP %d", resp.StatusCode)
	}
	return parseFirstA(body)
}

// buildQueryA crafts a minimal DNS query for A records.
func buildQueryA(name string) []byte {
	// ID=0x1234, flags RD, QDCOUNT=1
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)       // root
	msg = append(msg, 0x00, 0x01) // type A
	msg = append(msg, 0x00, 0x01) // class IN
	return msg
}

func parseFirstA(msg []byte) (net.IP, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("doh: short response")
	}
	ancount := int(msg[6])<<8 | int(msg[7])
	if ancount == 0 {
		return nil, fmt.Errorf("doh: no answers")
	}
	// Skip question
	i := 12
	for i < len(msg) {
		if msg[i] == 0 {
			i++
			break
		}
		if msg[i]&0xC0 == 0xC0 {
			i += 2
			break
		}
		i += int(msg[i]) + 1
	}
	i += 4 // type+class
	// First answer
	for a := 0; a < ancount && i < len(msg); a++ {
		if i+12 > len(msg) {
			break
		}
		if msg[i]&0xC0 == 0xC0 {
			i += 2
		} else {
			for i < len(msg) {
				if msg[i] == 0 {
					i++
					break
				}
				if msg[i]&0xC0 == 0xC0 {
					i += 2
					break
				}
				i += int(msg[i]) + 1
			}
		}
		if i+10 > len(msg) {
			break
		}
		typ := int(msg[i])<<8 | int(msg[i+1])
		rdlen := int(msg[i+8])<<8 | int(msg[i+9])
		i += 10
		if i+rdlen > len(msg) {
			break
		}
		if typ == 1 && rdlen == 4 {
			return net.IPv4(msg[i], msg[i+1], msg[i+2], msg[i+3]), nil
		}
		i += rdlen
	}
	return nil, fmt.Errorf("doh: no A record")
}
