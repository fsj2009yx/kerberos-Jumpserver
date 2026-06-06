package krb

import (
	"security-project/common/crypto"
	"security-project/common/krb/protocol"
)

const (
	KRBOK                 = protocol.KRBOK
	ErrMagicMismatch      = protocol.ErrMagicMismatch
	ErrVersionUnsupported = protocol.ErrVersionUnsupported
	ErrMsgTypeInvalid     = protocol.ErrMsgTypeInvalid
	ErrPayloadTooLarge    = protocol.ErrPayloadTooLarge
	ErrReplayTimestamp    = protocol.ErrReplayTimestamp
	ErrReplaySeq          = protocol.ErrReplaySeq
	ErrBufTooSmall        = protocol.ErrBufTooSmall
	ErrSocketSend         = protocol.ErrSocketSend
	ErrSocketRecv         = protocol.ErrSocketRecv
	ErrClientNotFound     = protocol.ErrClientNotFound
	ErrTicketExpired      = protocol.ErrTicketExpired
	ErrTicketInvalid      = protocol.ErrTicketInvalid
	ErrAuthMismatch       = protocol.ErrAuthMismatch
	ErrADMismatch         = protocol.ErrADMismatch
	ErrKeyDerive          = protocol.ErrKeyDerive
	ErrSessionNotFound    = protocol.ErrSessionNotFound
	ErrDESKeyLen          = protocol.ErrDESKeyLen
	ErrDESPadding         = protocol.ErrDESPadding
	ErrDESDecryptFail     = protocol.ErrDESDecryptFail
	ErrRSAKeyInvalid      = protocol.ErrRSAKeyInvalid
	ErrRSASignFail        = protocol.ErrRSASignFail
	ErrRSAVerifyFail      = protocol.ErrRSAVerifyFail
	ErrSHA256Fail         = protocol.ErrSHA256Fail
	ErrCertExpired        = protocol.ErrCertExpired
	ErrCertSigInvalid     = protocol.ErrCertSigInvalid
	ErrCertIDMismatch     = protocol.ErrCertIDMismatch
	ErrCertLoadFail       = protocol.ErrCertLoadFail

	MagicNumber = protocol.MagicNumber
	Version1    = protocol.Version1
	MsgASReq    = protocol.MsgASReq
	MsgASRep    = protocol.MsgASRep
	MsgTGSReq   = protocol.MsgTGSReq
	MsgTGSRep   = protocol.MsgTGSRep
	MsgAPReq    = protocol.MsgAPReq
	MsgAPRep    = protocol.MsgAPRep
	MsgApp      = protocol.MsgApp
	MsgErr      = protocol.MsgErr
)

type KString = protocol.KString
type ProtocolHeader = protocol.ProtocolHeader
type ASReqPayload = protocol.ASReqPayload
type ASRepPayloadWire = protocol.EncPackPayloadWire
type ASRepPlain = protocol.ASRepPlain
type TicketTGSPlain = protocol.TicketTGSPlain
type AuthenticatorCTGSPlain = protocol.AuthenticatorCTGSPlain
type TGSReqPayload = protocol.TGSReqPayload
type TGSRepPayloadWire = protocol.TGSRepPayloadWire
type TGSRepPlain = protocol.TGSRepPlain
type TicketVPlain = protocol.TicketVPlain
type APReqPayload = protocol.APReqPayload
type AuthenticatorCVPlain = protocol.AuthenticatorCVPlain
type APRepPayloadWire = protocol.APRepPayloadWire
type APRepPlain = protocol.APRepPlain
type APPReqPayload = protocol.APPReqPayload
type APPReqPlain = protocol.APPReqPlain
type APPRepPayload = protocol.APPRepPayload
type APPRepPlain = protocol.APPRepPlain
type Cursor = protocol.Cursor
type ASClientSecret = protocol.ASClientSecret
type ASState = protocol.ASState
type ServiceSecret = protocol.ServiceSecret
type TGSState = protocol.TGSState

func CodeName(code int32) string            { return protocol.CodeName(code) }
func CodeDescription(code int32) string     { return protocol.CodeDescription(code) }
func FormatCode(code int32) string          { return protocol.FormatCode(code) }
func DescribeCode(code int32) string        { return protocol.DescribeCode(code) }
func ErrorFromCode(code int32) error        { return protocol.ErrorFromCode(code) }
func CodeFromError(err error) int32         { return protocol.CodeFromError(err) }
func PeerErrorCode(err error) (int32, bool) { return protocol.PeerErrorCode(err) }

func NewCursor(data []byte) *Cursor                  { return protocol.NewCursor(data) }
func EncodeKString(s string) []byte                  { return protocol.EncodeKString(s) }
func DecodeKString(raw []byte) (KString, int, error) { return protocol.DecodeKString(raw) }
func EncodeKStringStruct(ks KString) []byte          { return protocol.EncodeKStringStruct(ks) }
func PackHeader(msgType uint8, seqNum, timestamp uint32, payloadLen uint32) []byte {
	return protocol.PackHeader(msgType, seqNum, timestamp, payloadLen)
}
func UnpackHeader(raw []byte) (ProtocolHeader, error) { return protocol.UnpackHeader(raw) }
func PackPacket(msgType uint8, seqNum, timestamp uint32, payload []byte) []byte {
	return protocol.PackPacket(msgType, seqNum, timestamp, payload)
}
func CheckHeaderType(msgType uint8, allowed ...uint8) error {
	return protocol.CheckHeaderType(msgType, allowed...)
}
func CheckPacketType(h ProtocolHeader, payload []byte, allowed ...uint8) error {
	return protocol.CheckPacketType(h, payload, allowed...)
}
func BuildErrorPayload(code int32) []byte             { return protocol.BuildErrorPayload(code) }
func ParseErrorPayload(payload []byte) (int32, error) { return protocol.ParseErrorPayload(payload) }

func ParseASReqPayload(raw []byte) (ASReqPayload, error) { return protocol.ParseASReqPayload(raw) }
func BuildTicketTGSPlain(c ASClientSecret, idTGS string, keyCTGS [8]byte, ts2 uint32, lifetime uint32) ([]byte, error) {
	return protocol.BuildTicketTGSPlain(c, idTGS, keyCTGS, ts2, lifetime)
}
func BuildASRepPlain(keyCTGS [8]byte, idTGS string, ts2 uint32, lifetime uint32, ticketTGS []byte) ([]byte, error) {
	return protocol.BuildASRepPlain(keyCTGS, idTGS, ts2, lifetime, ticketTGS)
}
func BuildEncPack(encPart []byte) ([]byte, error)            { return protocol.BuildEncPack(encPart) }
func ParseASRepPayload(raw []byte) (ASRepPayloadWire, error) { return protocol.ParseEncPack(raw) }

func ParseTGSReqPayload(raw []byte) (TGSReqPayload, error) { return protocol.ParseTGSReqPayload(raw) }
func DecodeTicketTGS(ticketCipher []byte, ktgs [8]byte) (TicketTGSPlain, error) {
	return protocol.DecodeTicketTGS(ticketCipher, ktgs)
}
func DecodeAuthenticatorCTGS(authCipher []byte, keyCTGS [8]byte) (AuthenticatorCTGSPlain, error) {
	return protocol.DecodeAuthenticatorCTGS(authCipher, keyCTGS)
}
func BuildTicketVPlain(idClient string, adC uint32, idV string, keyCV [8]byte, ts4 uint32, lifetime uint32) ([]byte, error) {
	return protocol.BuildTicketVPlain(idClient, adC, idV, keyCV, ts4, lifetime)
}
func BuildTGSRepPlain(keyCV [8]byte, idV string, ts4 uint32, lifetime uint32, ticketV []byte) ([]byte, error) {
	return protocol.BuildTGSRepPlain(keyCV, idV, ts4, lifetime, ticketV)
}

func ParseAPReqPayload(raw []byte) (APReqPayload, error) { return protocol.ParseAPReqPayload(raw) }
func DecodeTicketV(ticketCipher []byte, kv [8]byte) (TicketVPlain, error) {
	return protocol.DecodeTicketV(ticketCipher, kv)
}
func DecodeAuthenticatorCV(authCipher []byte, keyCV [8]byte) (AuthenticatorCVPlain, error) {
	return protocol.DecodeAuthenticatorCV(authCipher, keyCV)
}
func BuildAPRepPayload(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	return protocol.BuildAPRepPayload(ts5, keyCV)
}
func ParseAPPReqPayload(raw []byte) (APPReqPayload, error) { return protocol.ParseAPPReqPayload(raw) }
func DecryptAPPReqPlain(cipherBytes []byte, keyCV [8]byte) (APPReqPlain, error) {
	return protocol.DecryptAPPReqPlain(cipherBytes, keyCV)
}
func BuildAPPRepPayload(ptyEvent uint8, ptySessionID uint32, exitCode int32, payload []byte, keyCV [8]byte, signV func([]byte) ([256]byte, error)) ([]byte, error) {
	return protocol.BuildAPPRepPayload(ptyEvent, ptySessionID, exitCode, payload, keyCV, signV)
}
func BuildAPRepPlain(ts5 uint32, keyCV [8]byte) ([]byte, error) {
	return protocol.BuildAPRepPlain(ts5, keyCV)
}
func DecryptAPRepPlain(cipherBytes []byte, keyCV [8]byte) (APRepPlain, error) {
	return protocol.DecryptAPRepPlain(cipherBytes, keyCV)
}
func VerifyCipherSignature(seq uint32, cipherData []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return protocol.VerifyCipherSignature(seq, cipherData, sig, pub)
}
func SignSHA256(msg []byte, priv *crypto.RSAKey) ([256]byte, error) {
	return protocol.SignSHA256(msg, priv)
}
func VerifySHA256(msg []byte, sig [256]byte, pub *crypto.RSAKey) error {
	return protocol.VerifySHA256(msg, sig, pub)
}
func ParseAPPRepPayload(raw []byte) (APPRepPayload, error) { return protocol.ParseAPPRepPayload(raw) }
func DecryptAPPRepPlain(cipherBytes []byte, keyCV [8]byte) (APPRepPlain, error) {
	return protocol.DecryptAPPRepPlain(cipherBytes, keyCV)
}
