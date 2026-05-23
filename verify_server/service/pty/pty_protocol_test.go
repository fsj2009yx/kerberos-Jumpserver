package pty

import (
	"encoding/binary"
	"testing"
)

func TestParseOpenSSHPayload(t *testing.T) {
	target := []byte("prod-1")
	term := []byte("xterm-256color")
	payload := make([]byte, 0, 2+len(target)+2+len(term)+4)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(target)))
	payload = append(payload, tmp...)
	payload = append(payload, target...)
	binary.BigEndian.PutUint16(tmp, uint16(len(term)))
	payload = append(payload, tmp...)
	payload = append(payload, term...)
	binary.BigEndian.PutUint16(tmp, 120)
	payload = append(payload, tmp...)
	binary.BigEndian.PutUint16(tmp, 30)
	payload = append(payload, tmp...)

	gotTarget, gotTerm, gotCols, gotRows, err := ParseOpenSSHPayload(payload)
	if err != nil {
		t.Fatalf("ParseOpenSSHPayload returned error: %v", err)
	}
	if gotTarget != "prod-1" || gotTerm != "xterm-256color" || gotCols != 120 || gotRows != 30 {
		t.Fatalf("unexpected parsed payload target=%q term=%q cols=%d rows=%d", gotTarget, gotTerm, gotCols, gotRows)
	}
}

func TestParseOpenSSHPayloadRejectsEmptyTarget(t *testing.T) {
	payload := []byte{0x00, 0x00}
	if _, _, _, _, err := ParseOpenSSHPayload(payload); err == nil {
		t.Fatal("expected empty target payload to fail")
	}
}
