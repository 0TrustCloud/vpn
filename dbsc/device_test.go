package dbsc

import "testing"

func TestDeviceProofRoundTrip(t *testing.T) {
	dev, err := GenerateSoftwareDevice()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager([]byte("test-hmac-key-32-bytes-long!!!!!!"))
	m.RegisterDevice(dev.Thumbprint, dev.PublicKey, dev.Security)
	proof, err := dev.SignProof("nonce-abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyProof(proof); err != nil {
		t.Fatal(err)
	}
	ticket, err := m.MintTicket("alice", "default", dev.Thumbprint, "software")
	if err != nil {
		t.Fatal(err)
	}
	if ticket.ZeroRTTMode != "safe" {
		t.Fatalf("mode %s", ticket.ZeroRTTMode)
	}
	jwt, err := m.TicketJWT(ticket)
	if err != nil || jwt == "" {
		t.Fatal(err)
	}
}
