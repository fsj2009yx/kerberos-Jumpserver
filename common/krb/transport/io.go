//io.go - 处理Kerberos协议包的读写操作

package transport

import (
	"io"
	"net"
	"security-project/common/krb/protocol"
)

// ReadPacket 从连接中读取一个完整的协议包，返回解析后的协议头、负载数据和错误码
func ReadPacket(conn net.Conn, maxPayload uint32) (protocol.ProtocolHeader, []byte, error) {
	//解析前20字节的header
	headerBuf := make([]byte, 20)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return protocol.ProtocolHeader{}, nil, protocol.ErrorFromCode(protocol.ErrSocketRecv)
	}
	h, code := protocol.UnpackHeader(headerBuf)
	//校验header合法性
	if code != nil {
		return protocol.ProtocolHeader{}, nil, code
	}
	//校验payload长度
	if h.TotalLen > maxPayload {
		return protocol.ProtocolHeader{}, nil, protocol.ErrorFromCode(protocol.ErrPayloadTooLarge)
	}
	payload := make([]byte, h.TotalLen)
	if h.TotalLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return protocol.ProtocolHeader{}, nil, protocol.ErrorFromCode(protocol.ErrSocketRecv)
		}
	}
	return h, payload, nil
}

func WritePacket(conn net.Conn, msgType uint8, seqNum, timestamp uint32, payload []byte) error {
	packet := protocol.PackPacket(msgType, seqNum, timestamp, payload)
	_, err := conn.Write(packet)
	return err
}
