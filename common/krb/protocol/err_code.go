package protocol

import (
	"errors"
	"fmt"
)

// Status codes for Kerberos operations
const (
	KRBOK                 int32 = 0
	ErrMagicMismatch      int32 = -1001
	ErrVersionUnsupported int32 = -1002
	ErrMsgTypeInvalid     int32 = -1003
	ErrPayloadTooLarge    int32 = -1004
	ErrReplayTimestamp    int32 = -1005
	ErrReplaySeq          int32 = -1006
	ErrBufTooSmall        int32 = -1007
	ErrSocketSend         int32 = -1008
	ErrSocketRecv         int32 = -1009
	ErrClientNotFound     int32 = -2001
	ErrTicketExpired      int32 = -2002
	ErrTicketInvalid      int32 = -2003
	ErrAuthMismatch       int32 = -2004
	ErrADMismatch         int32 = -2005
	ErrKeyDerive          int32 = -2006
	ErrSessionNotFound    int32 = -2007
	ErrDESKeyLen          int32 = -3001
	ErrDESPadding         int32 = -3002
	ErrDESDecryptFail     int32 = -3003
	ErrRSAKeyInvalid      int32 = -3004
	ErrRSASignFail        int32 = -3005
	ErrRSAVerifyFail      int32 = -3006
	ErrSHA256Fail         int32 = -3008
	ErrCertExpired        int32 = -4001
	ErrCertSigInvalid     int32 = -4002
	ErrCertIDMismatch     int32 = -4003
	ErrCertLoadFail       int32 = -4004
)

type codeInfo struct {
	name        string
	description string
}

var codeInfoByCode = map[int32]codeInfo{
	KRBOK:                 {"KRB_OK", "operation succeeded"},
	ErrMagicMismatch:      {"ERR_MAGIC_MISMATCH", "protocol magic number mismatch"},
	ErrVersionUnsupported: {"ERR_VERSION_UNSUPPORTED", "protocol version is unsupported"},
	ErrMsgTypeInvalid:     {"ERR_MSG_TYPE_INVALID", "message type is invalid for this protocol stage"},
	ErrPayloadTooLarge:    {"ERR_PAYLOAD_TOO_LARGE", "payload length exceeds configured limit"},
	ErrReplayTimestamp:    {"ERR_REPLAY_TIMESTAMP", "message timestamp is outside the anti-replay window"},
	ErrReplaySeq:          {"ERR_REPLAY_SEQ", "message sequence number was already processed"},
	ErrBufTooSmall:        {"ERR_BUF_TOO_SMALL", "output buffer is too small"},
	ErrSocketSend:         {"ERR_SOCKET_SEND", "socket send failed"},
	ErrSocketRecv:         {"ERR_SOCKET_RECV", "socket receive failed or peer closed the connection"},
	ErrClientNotFound:     {"ERR_CLIENT_NOT_FOUND", "client id was not found"},
	ErrTicketExpired:      {"ERR_TICKET_EXPIRED", "ticket has expired"},
	ErrTicketInvalid:      {"ERR_TICKET_INVALID", "ticket is invalid or cannot be decoded"},
	ErrAuthMismatch:       {"ERR_AUTH_MISMATCH", "authenticator client id does not match ticket client id"},
	ErrADMismatch:         {"ERR_AD_MISMATCH", "client network address does not match ticket or authenticator"},
	ErrKeyDerive:          {"ERR_KEY_DERIVE", "session key generation failed"},
	ErrSessionNotFound:    {"ERR_SESSION_NOT_FOUND", "authenticated session was not found"},
	ErrDESKeyLen:          {"ERR_DES_KEY_LEN", "DES key length is invalid"},
	ErrDESPadding:         {"ERR_DES_PADDING", "DES plaintext padding failed"},
	ErrDESDecryptFail:     {"ERR_DES_DECRYPT_FAIL", "DES ciphertext decrypt or padding validation failed"},
	ErrRSAKeyInvalid:      {"ERR_RSA_KEY_INVALID", "RSA key is invalid"},
	ErrRSASignFail:        {"ERR_RSA_SIGN_FAIL", "RSA signing failed"},
	ErrRSAVerifyFail:      {"ERR_RSA_VERIFY_FAIL", "RSA signature verification failed"},
	ErrSHA256Fail:         {"ERR_SHA256_FAIL", "SHA-256 calculation failed"},
	ErrCertExpired:        {"ERR_CERT_EXPIRED", "certificate has expired"},
	ErrCertSigInvalid:     {"ERR_CERT_SIG_INVALID", "certificate signature is invalid"},
	ErrCertIDMismatch:     {"ERR_CERT_ID_MISMATCH", "certificate id does not match the expected client id"},
	ErrCertLoadFail:       {"ERR_CERT_LOAD_FAIL", "certificate file load or parse failed"},
}

func CodeName(code int32) string {
	if info, ok := codeInfoByCode[code]; ok {
		return info.name
	}
	return "ERR_UNKNOWN"
}

func CodeDescription(code int32) string {
	if info, ok := codeInfoByCode[code]; ok {
		return info.description
	}
	return "unknown Kerberos error code"
}

func FormatCode(code int32) string {
	return fmt.Sprintf("%s(%d)", CodeName(code), code)
}

func DescribeCode(code int32) string {
	return fmt.Sprintf("%s: %s", FormatCode(code), CodeDescription(code))
}

type codeError struct {
	code int32
}

func (e codeError) Error() string {
	return DescribeCode(e.code)
}

type peerCodeError struct {
	code int32
}

func (e peerCodeError) Error() string {
	return fmt.Sprintf("peer returned %s", DescribeCode(e.code))
}

func errorFromCode(code int32) error {
	if code == KRBOK {
		return nil
	}
	return codeError{code: code}
}

func ErrorFromCode(code int32) error {
	return errorFromCode(code)
}

func CodeFromError(err error) int32 {
	if err == nil {
		return KRBOK
	}
	var pe peerCodeError
	if errors.As(err, &pe) {
		return pe.code
	}
	var ce codeError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ErrTicketInvalid
}

func peerErrorFromCode(code int32) error {
	if code == KRBOK {
		return errorFromCode(ErrMsgTypeInvalid)
	}
	return peerCodeError{code: code}
}

func PeerErrorCode(err error) (int32, bool) {
	var pe peerCodeError
	if errors.As(err, &pe) {
		return pe.code, true
	}
	return 0, false
}
