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

	OpInput   = 0x02
	OpResize  = 0x03
	OpSignal  = 0x04
	OpClose   = 0x05
	OpOpenSSH = 0x06
)

// ParseOpenSSHPayload 解析远端 SSH PTY 打开请求的 payload，格式为：
// [targetLen(2 bytes)][target(targetLen bytes)][termLen(2 bytes)][term(termLen bytes)][cols(2 bytes)][rows(2 bytes)]
func ParseOpenSSHPayload(raw []byte) (string, string, uint16, uint16, error) {
	if len(raw) < 2 {
		return "", "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	targetLen := int(binary.BigEndian.Uint16(raw[:2]))
	offset := 2
	if targetLen <= 0 || len(raw) < offset+targetLen+2 {
		return "", "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	targetID := string(raw[offset : offset+targetLen])
	offset += targetLen

	termLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	if len(raw) < offset+termLen+4 {
		return "", "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	term := string(raw[offset : offset+termLen])
	offset += termLen
	cols := binary.BigEndian.Uint16(raw[offset : offset+2])
	rows := binary.BigEndian.Uint16(raw[offset+2 : offset+4])
	if cols == 0 || rows == 0 {
		return "", "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return targetID, term, cols, rows, nil
}

// ParseResizePayload ParseInputPayload 解析Input事件的payload，格式为：
// [dataLen(2 bytes)][data(dataLen bytes)]
// 其中dataLen为输入数据的长度，data为输入的数据内容
func ParseResizePayload(raw []byte) (uint16, uint16, error) {
	if len(raw) < 4 {
		return 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:4]), nil
}

// ParseSignalPayload 解析Signal事件的payload，格式为：
// [sig(1 byte)]
// 其中sig为信号的编号，具体信号编号可以参考Unix系统的信号定义，如1表示SIGHUP，2表示SIGINT，3表示SIGQUIT等
func ParseSignalPayload(raw []byte) (uint8, error) {
	if len(raw) < 1 {
		return 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return raw[0], nil
}
