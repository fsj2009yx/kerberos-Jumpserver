package krb

import (
	"strings"
	"testing"
)

func TestCheckHeaderTypeRejectsErrorMessage(t *testing.T) {
	if err := CheckHeaderType(MsgErr, MsgASReq); err == nil {
		t.Fatal("CheckHeaderType accepted MsgErr as a normal message type")
	}
	if err := CheckHeaderType(MsgErr, MsgErr); err == nil {
		t.Fatal("CheckHeaderType accepted MsgErr even when it was listed as allowed")
	}
}

func TestCheckPacketTypeReturnsPeerErrorCode(t *testing.T) {
	payload := BuildErrorPayload(ErrTicketExpired)
	err := CheckPacketType(ProtocolHeader{MsgType: MsgErr}, payload, MsgASReq)
	if err == nil {
		t.Fatal("CheckPacketType returned nil for MsgErr")
	}
	if got := CodeFromError(err); got != ErrTicketExpired {
		t.Fatalf("CodeFromError() = %d, want %d", got, ErrTicketExpired)
	}
	peerCode, ok := PeerErrorCode(err)
	if !ok {
		t.Fatal("PeerErrorCode did not recognize peer error")
	}
	if peerCode != ErrTicketExpired {
		t.Fatalf("PeerErrorCode() = %d, want %d", peerCode, ErrTicketExpired)
	}
	if msg := err.Error(); !strings.Contains(msg, "ERR_TICKET_EXPIRED(-2002)") || !strings.Contains(msg, "ticket has expired") {
		t.Fatalf("peer error string missing code description: %q", msg)
	}
}

func TestParseErrorPayloadRejectsMalformedPayload(t *testing.T) {
	if _, err := ParseErrorPayload([]byte{0x01, 0x02}); err == nil {
		t.Fatal("ParseErrorPayload accepted short payload")
	}
	if _, err := ParseErrorPayload(BuildErrorPayload(KRBOK)); err == nil {
		t.Fatal("ParseErrorPayload accepted KRBOK as an error payload")
	}
}

func TestErrorFromCodeIncludesLogDescription(t *testing.T) {
	err := ErrorFromCode(ErrReplaySeq)
	if err == nil {
		t.Fatal("ErrorFromCode returned nil for ErrReplaySeq")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ERR_REPLAY_SEQ(-1006)") {
		t.Fatalf("error string missing code name: %q", msg)
	}
	if !strings.Contains(msg, "sequence number") {
		t.Fatalf("error string missing description: %q", msg)
	}
}
