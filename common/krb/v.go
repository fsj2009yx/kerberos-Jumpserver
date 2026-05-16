package krb

import (
	"bytes"
	"encoding/binary"
	"security-project/common/crypto"
)

func ParseAPReqPayload(raw []byte) (APReqPayload, error) {
	c := NewCursor(raw)
	ticketLen, err := c.ReadUint32()
	if err != nil {
		return APReqPayload{}, err
	}
	ticket, err := c.ReadBytes(int(ticketLen))
	if err != nil {
		return APReqPayload{}, err
	}
	authLen, err := c.ReadUint32()
	if err != nil {
		return APReqPayload{}, err
	}
	authCipher, err := c.ReadBytes(int(authLen))
	if err != nil {
		return APReqPayload{}, err
	}
	return APReqPayload{
		TicketVLen: ticketLen,
		TicketV:    ticket,
		AuthLen:    authLen,
		AuthCipher: authCipher,
	}, nil
}

func DecodeTicketV(ticketCipher []byte, kv [8]byte) (TicketVPlain, error) {
	plain, err := crypto.DecryptDESCBC(kv, ticketCipher)
	if err != nil {
		return TicketVPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	keyBytes, err := c.ReadBytes(8)
	if err != nil {
		return TicketVPlain{}, err
	}
	idClient, err := c.ReadKString()
	if err != nil {
		return TicketVPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	idV, err := c.ReadKString()
	if err != nil {
		return TicketVPlain{}, err
	}
	ts4, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	lifetime, err := c.ReadUint32()
	if err != nil {
		return TicketVPlain{}, err
	}
	var out TicketVPlain
	copy(out.KeyCV[:], keyBytes)
	out.IDClient = idClient
	out.ADc = adc
	out.IDV = idV
	out.TS4 = ts4
	out.Lifetime = lifetime
	return out, nil
}

func DecodeAuthenticatorCV(authCipher []byte, keyCV [8]byte) (AuthenticatorCVPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, authCipher)
	if err != nil {
		return AuthenticatorCVPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	idClient, err := c.ReadKString()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	adc, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	ts5, err := c.ReadUint32()
	if err != nil {
		return AuthenticatorCVPlain{}, err
	}
	return AuthenticatorCVPlain{
		IDClient: idClient,
		ADc:      adc,
		TS5:      ts5,
	}, nil
}

func BuildAPRepPayload(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, ts5+1)
	cipherData, err := crypto.EncryptDESCBC(keyCV, tmp)
	if err != nil {
		return nil, errorFromCode(ErrDESPadding)
	}
	return BuildASRepPayload(cipherData)
}

// ParseAPPReqPayload 解析AP-REQ消息的负载，返回一个APPReqPayload结构体和错误信息
func ParseAPPReqPayload(raw []byte) (APPReqPayload, error) {
	c := NewCursor(raw)
	idClient, err := c.ReadKString()
	if err != nil {
		return APPReqPayload{}, err
	}
	cipherLen, err := c.ReadUint16()
	if err != nil {
		return APPReqPayload{}, err
	}
	cipher, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return APPReqPayload{}, err
	}
	sigBytes, err := c.ReadBytes(256)
	if err != nil {
		return APPReqPayload{}, err
	}
	var sig [256]byte
	copy(sig[:], sigBytes)
	return APPReqPayload{
		IDClient:  idClient,
		CipherLen: cipherLen,
		Cipher:    cipher,
		RSASignC:  sig,
	}, nil
}

// DecryptAPPReqPlain 解密AP-REQ消息中的密文数据，返回一个APPReqPlain结构体和错误信息
func DecryptAPPReqPlain(cipherBytes []byte, keyCV [8]byte) (APPReqPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPReqPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	ptyOp, err := c.ReadBytes(1)
	if err != nil {
		return APPReqPlain{}, err
	}
	ptySessionID, err := c.ReadUint32()
	if err != nil {
		return APPReqPlain{}, err
	}
	payloadLen, err := c.ReadUint32()
	if err != nil {
		return APPReqPlain{}, err
	}
	payload, err := c.ReadBytes(int(payloadLen))
	if err != nil {
		return APPReqPlain{}, err
	}
	return APPReqPlain{
		PtyOp:        ptyOp[0],
		PtySessionID: ptySessionID,
		PayloadLen:   payloadLen,
		Payload:      payload,
	}, nil
}

// BuildAPPRepPayload 构建AP-REP消息的负载，包含一个APPRepPayload结构体和错误信息
// ptyEvent: 终端事件类型，例如窗口大小变化、输入事件等
// ptySessionID: 终端会话ID，用于区分不同的终端会话
// exitCode: 终端会话的退出代码，表示会话结束的原因
// payload: 终端事件的具体数据，例如新的窗口大小、输入内容等
// keyCV: 用于加密和解密的密钥，长度为8字节
func BuildAPPRepPayload(ptyEvent uint8, ptySessionID uint32, exitCode int32, payload []byte, keyCV [8]byte, signV func([]byte) ([256]byte, error)) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)
	body.WriteByte(ptyEvent)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, ptySessionID)
	body.Write(tmp4)
	binary.BigEndian.PutUint32(tmp4, uint32(exitCode))
	body.Write(tmp4)
	binary.BigEndian.PutUint32(tmp4, uint32(len(payload)))
	body.Write(tmp4)
	body.Write(payload)
	cipherData, err := crypto.EncryptDESCBC(keyCV, body.Bytes())
	if err != nil {
		return nil, errorFromCode(ErrDESPadding)
	}
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, uint16(len(cipherData)))
	buf.Write(tmp2)
	buf.Write(cipherData)
	sig, err := signV(cipherData)
	if err != nil {
		return nil, err
	}
	buf.Write(sig[:])
	return buf.Bytes(), nil
}

func BuildAPRepPlain(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	return BuildAPRepPayload(ts5, keyCV)
}

func DecryptAPRepPlain(cipherBytes []byte, keyCV [8]byte) (APRepPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APRepPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	if len(plain) < 4 {
		return APRepPlain{}, errorFromCode(ErrTicketInvalid)
	}
	return APRepPlain{
		TS5Plus1: binary.BigEndian.Uint32(plain[:4]),
	}, nil
}

// VerifyCipherSignature 验证密文数据的RSA签名，返回一个错误信息
func VerifyCipherSignature(seq uint32, cipherData []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return errorFromCode(crypto.RsaVerifySignature(seq, cipherData, sig, pub))
}

func SignSHA256(msg []byte, priv *crypto.RSAKey) ([256]byte, error) {
	sig, code := crypto.RsaSignMessage(msg, priv)
	return sig, errorFromCode(code)
}

func VerifySHA256(msg []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return errorFromCode(crypto.RsaVerifyMessage(msg, sig, pub))
}

func ParseAPPRepPayload(raw []byte) (APPRepPayload, error) {
	c := NewCursor(raw)
	cipherLen, err := c.ReadUint16()
	if err != nil {
		return APPRepPayload{}, err
	}
	cipher, err := c.ReadBytes(int(cipherLen))
	if err != nil {
		return APPRepPayload{}, err
	}
	sigBytes, err := c.ReadBytes(256)
	if err != nil {
		return APPRepPayload{}, err
	}
	var sig [256]byte
	copy(sig[:], sigBytes)
	return APPRepPayload{
		CipherLen: cipherLen,
		Cipher:    cipher,
		RSASignV:  sig,
	}, nil
}

func DecryptAPPRepPlain(cipherBytes []byte, keyCV [8]byte) (APPRepPlain, error) {
	plain, err := crypto.DecryptDESCBC(keyCV, cipherBytes)
	if err != nil {
		return APPRepPlain{}, errorFromCode(ErrDESDecryptFail)
	}
	c := NewCursor(plain)
	ptyEvent, err := c.ReadBytes(1)
	if err != nil {
		return APPRepPlain{}, err
	}
	ptySessionID, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	exitCode, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	payloadLen, err := c.ReadUint32()
	if err != nil {
		return APPRepPlain{}, err
	}
	payload, err := c.ReadBytes(int(payloadLen))
	if err != nil {
		return APPRepPlain{}, err
	}
	return APPRepPlain{
		PtyEvent:     ptyEvent[0],
		PtySessionID: ptySessionID,
		ExitCode:     int32(exitCode),
		PayloadLen:   payloadLen,
		Payload:      payload,
	}, nil
}
