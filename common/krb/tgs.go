package krb

import (
	"bytes"
	"encoding/binary"
	"security-project/common/crypto"
)

type ServiceSecret struct {
	IDV string
	Kv  [8]byte
}

// TGSState 包含了 TGS 服务器的状态信息
// 包括一个序列号 SeqNum、TGS 密钥 Ktgs、TGS 的 ID 和一个映射 Services，键是服务 ID，值是包含服务 ID 和与 TGS 共享的密钥的结构体 ServiceSecret。
type TGSState struct {
	SeqNum   uint32
	Ktgs     [8]byte
	IDTGS    string
	Services map[string]ServiceSecret
}

func ParseTGSReqPayload(raw []byte) (TGSReqPayload, error) {
	c := NewCursor(raw)
	idV, err := c.ReadKString()
	if err != nil {
		return TGSReqPayload{}, err
	}
	ticketLen, err := c.ReadUint32()
	if err != nil {
		return TGSReqPayload{}, err
	}
	ticketTGS, err := c.ReadBytes(int(ticketLen))
	if err != nil {
		return TGSReqPayload{}, err
	}
	authLen, err := c.ReadUint32()
	if err != nil {
		return TGSReqPayload{}, err
	}
	authCipher, err := c.ReadBytes(int(authLen))
	if err != nil {
		return TGSReqPayload{}, err
	}
	return TGSReqPayload{
		IDV:        idV,
		TicketLen:  ticketLen,
		TicketTGS:  ticketTGS,
		AuthLen:    authLen,
		AuthCipher: authCipher,
	}, nil
}

func DecodeTicketTGS(ticketCipher []byte, ktgs [8]byte) (TicketTGSPlain, error) {
	plain, err := crypto.DecryptDESCBC(ktgs, ticketCipher)
	if err != nil {
		return TicketTGSPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	keyBytes, err := c.ReadBytes(8)
	if err != nil {
		return TicketTGSPlain{}, err
	}
	idClient, err := c.ReadKString()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	idTGS, err := c.ReadKString()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	ts2, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	lifetime, err := c.ReadUint32()
	if err != nil {
		return TicketTGSPlain{}, err
	}
	var key TicketTGSPlain
	copy(key.KeyCTGS[:], keyBytes)
	key.IDClient = idClient
	key.ADc = adc
	key.IDTGS = idTGS
	key.TS2 = ts2
	key.Lifetime = lifetime
	return key, nil
}

func DecodeAuthenticatorCTGS(authCipher []byte, keyCTGS [8]byte) (AuthenticatorCTGSPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCTGS, authCipher)
	if err != nil {
		return AuthenticatorCTGSPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	idClient, err := c.ReadKString()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	ts3, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCTGSPlain{}, err
	}
	return AuthenticatorCTGSPlain{
		IDClient: idClient,
		ADc:      adc,
		TS3:      ts3,
	}, nil
}

func BuildTicketVPlain(idClient string, adC uint32, idV string, keyCV [8]byte, ts4 uint32, lifetime uint32) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCV[:])
	buf.Write(EncodeKString(idClient))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, adC)
	buf.Write(tmp)
	buf.Write(EncodeKString(idV))
	binary.BigEndian.PutUint32(tmp, ts4)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	return buf.Bytes(), nil
}

func BuildTGSRepPlain(keyCV [8]byte, idV string, ts4 uint32, lifetime uint32, ticketV []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(keyCV[:])
	buf.Write(EncodeKString(idV))
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts4)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, lifetime)
	buf.Write(tmp)
	binary.BigEndian.PutUint32(tmp, uint32(len(ticketV)))
	buf.Write(tmp)
	buf.Write(ticketV)
	return buf.Bytes(), nil
}
