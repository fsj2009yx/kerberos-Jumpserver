package service

import (
	"net"
	"testing"
	"time"

	"security-project/common/krb"
	"security-project/verify_server/config"
)

func TestHandleConnectionClosesOnPeerErrorPacket(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	svc := &Service{
		Config: &config.Config{
			AntiReplayWindow: 8,
			MaxPayloadBytes:  64,
			ReadTimeoutSec:   1,
		},
	}

	done := make(chan struct{})
	go func() {
		svc.handleConnection(serverConn)
		close(done)
	}()

	if err := krb.WritePacket(clientConn, krb.MsgErr, 1, uint32(time.Now().Unix()), krb.BuildErrorPayload(krb.ErrTicketExpired)); err != nil {
		t.Fatalf("write peer error packet: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 20)
	if n, err := clientConn.Read(buf); err == nil {
		t.Fatalf("expected connection close without response, read %d bytes", n)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleConnection did not return after peer error packet")
	}
}
