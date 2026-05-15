//connection.go用于管理每个连接的状态，包括认证状态、重放窗口、发送序列号等
//它提供了读取和发送数据包的方法，并且在连接关闭时进行清理

package service

import (
	"context"
	"net"
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

	authed  bool
	current *SessionContext
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

func (c *ConnState) readPacket(readTimeoutSec int, maxPayloadBytes uint32) (krb.ProtocolHeader, []byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeoutSec) * time.Second))
	return krb.ReadPacket(c.conn, maxPayloadBytes)
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
	err := krb.WritePacket(c.conn, msgType, seq, uint32(time.Now().Unix()), payload)
	if err != nil {
		log.Errorf("[V] packet send failed remote=%s msg_type=%d seq=%d err=%v", c.remote, msgType, seq, err)
		return err
	}
	log.Infof("[V] packet sent remote=%s msg_type=%d seq=%d payload_bytes=%d", c.remote, msgType, seq, len(payload))
	return nil
}

func (c *ConnState) writeError(seq uint32, code int32) error {
	err := c.sendPacketWithSeq(krb.MsgErr, seq, krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[V] error response send failed seq=%d code=%d err=%v", seq, code, err)
		return err
	}
	log.Warnf("[V] error response sent seq=%d code=%d", seq, code)
	return nil
}

func (c *ConnState) close() {
	c.cancel()
	_ = c.conn.Close()
	log.Infof("[V] connection closed remote=%s", c.remote)
}
