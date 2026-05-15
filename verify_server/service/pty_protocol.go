package service

import (
	"encoding/binary"

	"security-project/common/krb"
)

const (
	ptyEventOpenOK = 0x11
	ptyEventOutput = 0x12
	ptyEventExit   = 0x13
	ptyEventError  = 0x14

	ptyOpOpen   = 0x01
	ptyOpInput  = 0x02
	ptyOpResize = 0x03
	ptyOpSignal = 0x04
	ptyOpClose  = 0x05
)

func parsePtyOpenPayload(raw []byte) (string, uint16, uint16, error) {
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

func parsePtyResizePayload(raw []byte) (uint16, uint16, error) {
	if len(raw) < 4 {
		return 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:4]), nil
}

func parsePtySignalPayload(raw []byte) (uint8, error) {
	if len(raw) < 1 {
		return 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return raw[0], nil
}
