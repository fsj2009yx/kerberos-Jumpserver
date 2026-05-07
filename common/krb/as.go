package krb

import (
	"bytes"
	"encoding/binary"
)

// ASClientSecret 是AS服务器中保存的客户端信息结构体，包含了客户端的ID、与TGS共享的密钥以及客户端的ADc（地址）。
type ASClientSecret struct {
	IDClient string
	Kc       [8]byte
	ADc      uint32
}

// ASState 是AS服务器的状态结构体，包含了当前的序列号、客户端信息、TGS的密钥以及TGS的ID。
type ASState struct {
	SeqNum  uint32
	Clients map[string]ASClientSecret
	Ktgs    [8]byte
	IDTGS   string
}

// ParseASReqPayload 解析错误消息的负载，返回错误码
func ParseASReqPayload(raw []byte) (ASReqPayload, error) {
	c := NewCursor(raw)
	idClient, err := c.ReadKString()
	if err != nil {
		return ASReqPayload{}, err
	}
	idTGS, err := c.ReadKString()
	if err != nil {
		return ASReqPayload{}, err
	}
	ts1, err := c.ReadUint32()
	if err != nil {
		return ASReqPayload{}, err
	}
	return ASReqPayload{
		IDClient: idClient,
		IDTGS:    idTGS,
		TS1:      ts1,
	}, nil
}

func BuildTicketTGSPlain(c ASClientSecret, idTGS string, keyCTGS [8]byte, ts2 uint32, lifetime uint32) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCTGS[:])
	buf.Write(EncodeKString(c.IDClient))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, c.ADc)
	buf.Write(tmp)
	buf.Write(EncodeKString(idTGS))
	binary.BigEndian.PutUint32(tmp, ts2)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	return buf.Bytes(), nil
}

func BuildASRepPlain(keyCTGS [8]byte, idTGS string, ts2 uint32, lifetime uint32, ticketTGS []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCTGS[:])
	buf.Write(EncodeKString(idTGS))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts2)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, uint32(len(ticketTGS)))
	buf.Write(tmp)
	buf.Write(ticketTGS)
	return buf.Bytes(), nil
}

func BuildASRepPayload(encPart []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(len(encPart)))
	buf.Write(tmp)
	buf.Write(encPart)
	return buf.Bytes(), nil
}

func ParseASRepPayload(raw []byte) (ASRepPayloadWire, error) {
	c := NewCursor(raw)
	cipherLen, err := c.ReadUint32()
	if err != nil {
		return ASRepPayloadWire{}, err
	}
	encPart, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return ASRepPayloadWire{}, err
	}
	return ASRepPayloadWire{
		CipherLen: cipherLen,
		EncPart:   encPart,
	}, nil
}
