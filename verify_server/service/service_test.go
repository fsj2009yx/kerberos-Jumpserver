package service

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"security-project/common/krb"
	"security-project/verify_server/config"
	"security-project/verify_server/service/pty"
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

type closeCountingPTY struct {
	closed atomic.Int32
}

func (p *closeCountingPTY) Read(_ []byte) (int, error) {
	return 0, net.ErrClosed
}

func (p *closeCountingPTY) Write(data []byte) (int, error) {
	return len(data), nil
}

func (p *closeCountingPTY) Close() error {
	p.closed.Add(1)
	return nil
}

func TestCleanupSessionClosesPTYAndRemovesOnlyCurrentSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ptyHandle := &closeCountingPTY{}
	oldSession := &SessionContext{
		IDClient:     "CLIENT_1",
		PtySessionID: 7,
		PTY:          &pty.Session{PTY: ptyHandle},
		Ctx:          ctx,
		Cancel:       cancel,
	}
	newSession := &SessionContext{IDClient: "CLIENT_1", PtySessionID: 8}
	svc := &Service{
		state: &VState{Sessions: map[string]*SessionContext{
			oldSession.IDClient: newSession,
		}},
	}

	svc.cleanupSession(oldSession, "test disconnect")

	if ptyHandle.closed.Load() != 1 {
		t.Fatalf("expected old pty to be closed once, got %d", ptyHandle.closed.Load())
	}
	if !oldSession.Closed.Load() {
		t.Fatal("expected old session to be marked closed")
	}
	if got := svc.state.Sessions["CLIENT_1"]; got != newSession {
		t.Fatalf("cleanup removed/replaced the active session: got=%p want=%p", got, newSession)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected session context to be canceled")
	}
}

func TestCleanupPTYClosesConnectionKeepsKerberosSessionAndAudits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ptyHandle := &closeCountingPTY{}
	sess := &SessionContext{
		IDClient:     "CLIENT_1",
		ClientIP:     "127.0.0.1:12345",
		ADc:          1,
		TargetID:     "prod-1",
		TargetHost:   "10.0.0.11:22",
		SSHUser:      "kerberosTest",
		PtySessionID: 9,
		PTY:          &pty.Session{PTY: ptyHandle},
		Ctx:          ctx,
		Cancel:       cancel,
	}
	audit, err := NewAuditStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("new audit store: %v", err)
	}
	defer audit.Close()
	svc := &Service{
		state: &VState{Sessions: map[string]*SessionContext{
			sess.IDClient: sess,
		}},
		audit: audit,
	}

	svc.cleanupPTY(sess, "app connection close")

	if ptyHandle.closed.Load() != 1 {
		t.Fatalf("expected pty to be closed once, got %d", ptyHandle.closed.Load())
	}
	if !sess.Closed.Load() {
		t.Fatal("expected pty state to be marked closed")
	}
	if sess.PTY != nil {
		t.Fatal("expected pty handle to be cleared")
	}
	if sess.PtySessionID != 0 || sess.TargetID != "" || sess.TargetHost != "" || sess.SSHUser != "" {
		t.Fatalf("expected active pty metadata to be cleared, got pty=%d target=%q host=%q user=%q", sess.PtySessionID, sess.TargetID, sess.TargetHost, sess.SSHUser)
	}
	if got := svc.state.Sessions["CLIENT_1"]; got != sess {
		t.Fatalf("expected kerberos session to remain, got=%p want=%p", got, sess)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected pty context to be canceled")
	}

	records, err := audit.Records(10, nil)
	if err != nil {
		t.Fatalf("read audit records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one cleanup audit record, got %d", len(records))
	}
	rec := records[0]
	if rec.EventType != "PTY_CLEANUP" || rec.FrameType != "app connection close" || rec.TargetID != "prod-1" || rec.PTYSessionID != 9 {
		t.Fatalf("unexpected cleanup audit record: %+v", rec)
	}

	svc.cleanupPTY(sess, "app connection close")
	if ptyHandle.closed.Load() != 1 {
		t.Fatalf("expected cleanup to be idempotent, close count=%d", ptyHandle.closed.Load())
	}
	records, err = audit.Records(10, nil)
	if err != nil {
		t.Fatalf("read audit records after second cleanup: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected no duplicate cleanup audit record, got %d", len(records))
	}
}
