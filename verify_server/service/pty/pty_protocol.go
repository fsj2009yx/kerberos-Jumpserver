package pty

import (
	"encoding/binary"

	"security-project/common/krb"
)

const (
	EventOpenOK = 0x11
	EventOutput = 0x12
	EventExit   = 0x13
	EventError  = 0x14

	OpOpen   = 0x01
	OpInput  = 0x02
	OpResize = 0x03
	OpSignal = 0x04
	OpClose  = 0x05
)

func ParseOpenPayload(raw []byte) (string, uint16, uint16, error) {
	if len(raw) < 2 {
		return "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	termLen := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+termLen+4 {
		return "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	term := string(raw[2 : 2+termLen])
	cols := binary.BigEndian.Uint16(raw[2+termLen : 2+termLen+2])
	rows := binary.BigEndian.Uint16(raw[2+termLen+2 : 2+termLen+4])
	return term, cols, rows, nil
}

func ParseResizePayload(raw []byte) (uint16, uint16, error) {
	if len(raw) < 4 {
		return 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:4]), nil
}

func ParseSignalPayload(raw []byte) (uint8, error) {
	if len(raw) < 1 {
		return 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return raw[0], nil
}
