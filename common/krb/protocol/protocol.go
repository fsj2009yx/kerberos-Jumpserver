package protocol

import "encoding/binary"

func EncodeKString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out[:2], uint16(len(s)))
	copy(out[2:], s)
	return out
}

// DecodeKString 解析KString格式的数据，返回KString结构体、总字节数和错误码。
func DecodeKString(raw []byte) (KString, int, error) {
	c := NewCursor(raw)
	ks, err := c.ReadKString()
	if err != nil {
		return KString{}, 0, err
	}
	return ks, c.off, nil
}

func EncodeKStringStruct(ks KString) []byte {
	if int(ks.Len) != len(ks.Data) {
		ks.Len = uint16(len(ks.Data))
	}
	out := make([]byte, 2+len(ks.Data))
	binary.BigEndian.PutUint16(out[:2], ks.Len)
	copy(out[2:], ks.Data)
	return out
}

// PackHeader 构建协议头，包含消息类型、序列号、时间戳和负载长度。
func PackHeader(msgType uint8, seqNum, timestamp uint32, payloadLen uint32) []byte {
	out := make([]byte, 20)
	binary.BigEndian.PutUint16(out[0:2], MagicNumber)
	out[2] = Version1
	out[3] = msgType
	binary.BigEndian.PutUint32(out[4:8], payloadLen)
	binary.BigEndian.PutUint32(out[8:12], seqNum)
	binary.BigEndian.PutUint32(out[12:16], timestamp)
	binary.BigEndian.PutUint32(out[16:20], 0)
	return out
}

// UnpackHeader 从原始字节解析协议头，并校验魔数和版本号。
func UnpackHeader(raw []byte) (ProtocolHeader, error) {
	if len(raw) < 20 {
		return ProtocolHeader{}, errorFromCode(ErrSocketRecv)
	}
	h := ProtocolHeader{
		Magic:     binary.BigEndian.Uint16(raw[0:2]),
		Version:   raw[2],
		MsgType:   raw[3],
		TotalLen:  binary.BigEndian.Uint32(raw[4:8]),
		SeqNum:    binary.BigEndian.Uint32(raw[8:12]),
		Timestamp: binary.BigEndian.Uint32(raw[12:16]),
		Addition:  binary.BigEndian.Uint32(raw[16:20]),
	}
	if h.Magic != MagicNumber {
		return ProtocolHeader{}, errorFromCode(ErrMagicMismatch)
	}
	if h.Version != Version1 {
		return ProtocolHeader{}, errorFromCode(ErrVersionUnsupported)
	}
	return h, nil
}

func PackPacket(msgType uint8, seqNum, timestamp uint32, payload []byte) []byte {
	header := PackHeader(msgType, seqNum, timestamp, uint32(len(payload)))
	return append(header, payload...)
}

// CheckHeaderType 检查消息类型是否在当前处理入口允许的范围内。
func CheckHeaderType(msgType uint8, allowed ...uint8) error {
	if msgType == MsgErr {
		return errorFromCode(ErrMsgTypeInvalid)
	}
	for _, v := range allowed {
		if v == msgType {
			return nil
		}
	}
	return errorFromCode(ErrMsgTypeInvalid)
}

// CheckPacketType 检查完整报文类型。收到 MsgErr 时返回对端错误码。
func CheckPacketType(h ProtocolHeader, payload []byte, allowed ...uint8) error {
	if h.MsgType == MsgErr {
		code, err := ParseErrorPayload(payload)
		if err != nil {
			return err
		}
		return peerErrorFromCode(code)
	}
	return CheckHeaderType(h.MsgType, allowed...)
}

// BuildErrorPayload 构建包含错误码的错误消息负载。
func BuildErrorPayload(code int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(code))
	return buf
}

func ParseErrorPayload(payload []byte) (int32, error) {
	if len(payload) != 4 {
		return KRBOK, errorFromCode(ErrMsgTypeInvalid)
	}
	code := int32(binary.BigEndian.Uint32(payload[:4]))
	if code == KRBOK {
		return KRBOK, errorFromCode(ErrMsgTypeInvalid)
	}
	return code, nil
}
