//connection.go用于管理每个连接的状态，包括认证状态、重放窗口、发送序列号等
//它提供了读取和发送数据包的方法，并且在连接关闭时进行清理

package service

import (
	"context"
	"net"
	"security-project/common/krb/transport"
	"sync"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

type ConnState struct {
	conn   net.Conn
	remote string

	ctx    context.Context
	cancel context.CancelFunc

	replay  *krb.ReplayWindow
	sendSeq uint32
	writeMu sync.Mutex

	//authed表示连接是否已经通过认证，只有在认证成功后才允许进行后续的操作，如创建会话、执行命令等
	authed bool
	// current字段指向当前的SessionContext，表示当前连接正在处理哪个会话
	//当连接接收到一个新的请求时，会根据请求中的信息找到对应的SessionContext，并将其赋值给current字段，以便后续的操作能够正确地关联到该会话。
	current  *SessionContext
	appBound bool
}

func NewConnState(conn net.Conn, antiReplayWindow int) *ConnState {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnState{
		conn:   conn,
		remote: conn.RemoteAddr().String(),
		ctx:    ctx,
		cancel: cancel,
		replay: krb.NewReplayWindow(antiReplayWindow),
	}
}

func (c *ConnState) closeOnCancel() {
	go func() {
		<-c.ctx.Done()
		_ = c.conn.Close()
	}()
}

func (c *ConnState) readPacket(maxPayloadBytes uint32) (krb.ProtocolHeader, []byte, error) {
	// 长连接不需要设置读取超时
	//_ = c.conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutSec) * time.Second))
	return transport.ReadPacket(c.conn, maxPayloadBytes)
}

func (c *ConnState) nextSeq() uint32 {
	seq := atomic.AddUint32(&c.sendSeq, 1)
	if seq == 0 {
		return atomic.AddUint32(&c.sendSeq, 1)
	}
	return seq
}

func (c *ConnState) sendPacket(msgType uint8, payload []byte) error {
	return c.sendPacketWithSeq(msgType, c.nextSeq(), payload)
}

func (c *ConnState) sendPacketWithSeq(msgType uint8, seq uint32, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	err := transport.WritePacket(c.conn, msgType, seq, uint32(time.Now().Unix()), payload)
	if err != nil {
		log.Errorf("[V] packet send failed remote=%s msg_type=%d seq=%d err=%v", c.remote, msgType, seq, err)
		c.cancel()
		return err
	}
	log.Infof("[V] packet sent remote=%s msg_type=%d seq=%d payload_bytes=%d", c.remote, msgType, seq, len(payload))
	return nil
}

func (c *ConnState) writeError(seq uint32, code int32) error {
	err := c.sendPacketWithSeq(krb.MsgErr, seq, krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[V] error response send failed seq=%d code=%s desc=%q err=%v", seq, krb.FormatCode(code), krb.CodeDescription(code), err)
		return err
	}
	log.Warnf("[V] error response sent seq=%d code=%s desc=%q", seq, krb.FormatCode(code), krb.CodeDescription(code))
	return nil
}

func (c *ConnState) close() {
	c.cancel()
	_ = c.conn.Close()
	log.Infof("[V] connection closed remote=%s", c.remote)
}
