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

type connectionState struct {
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

func newConnectionState(s *Service, conn net.Conn) *connectionState {
	ctx, cancel := context.WithCancel(context.Background())
	return &connectionState{
		service: s,
		conn:    conn,
		remote:  conn.RemoteAddr().String(),
		ctx:     ctx,
		cancel:  cancel,
		replay:  krb.NewReplayWindow(s.Config.AntiReplayWindow),
	}
}

func (s *Service) handleConnection(conn net.Conn) {
	c := newConnectionState(s, conn)
	c.run()
}

func (c *connectionState) run() {
	defer c.close()
	go func() {
		<-c.ctx.Done()
		_ = c.conn.Close()
	}()

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(time.Duration(c.service.Config.ReadTimeoutSec) * time.Second))
		h, payload, err := krb.ReadPacket(c.conn, c.service.Config.MaxPayloadBytes)
		if err != nil {
			code := krb.CodeFromError(err)
			if code != krb.ErrSocketRecv {
				log.Warnf("[V] read packet failed remote=%s code=%d err=%v", c.remote, code, err)
				_ = c.writeError(c.nextSeq(), code)
			}
			return
		}
		log.Infof("[V] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d authed=%t", c.remote, h.MsgType, h.SeqNum, len(payload), c.authed)
		switch h.MsgType {
		case krb.MsgAPReq:
			if c.handleAPPacket(h, payload) {
				continue
			}
			return
		case krb.MsgApp:
			if c.handleAPPPacket(h, payload) {
				continue
			}
			return
		default:
			log.Warnf("[V] invalid message type remote=%s msg_type=%d seq=%d", c.remote, h.MsgType, h.SeqNum)
			_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
			return
		}
	}
}

func (c *connectionState) handleAPPacket(h krb.ProtocolHeader, payload []byte) bool {
	if c.authed {
		log.Warnf("[V] duplicate AP_REQ remote=%s seq=%d", c.remote, h.SeqNum)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
		return false
	}
	if err := c.replay.Check(h.Timestamp, h.SeqNum); err != nil {
		log.Warnf("[V] AP replay check failed remote=%s seq=%d err=%v", c.remote, h.SeqNum, err)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	respPayload, sess, err := c.service.handleAPReq(c.ctx, h, payload, c.sendPacket)
	if err != nil {
		log.Warnf("[V] AP_REQ handling failed remote=%s seq=%d err=%v", c.remote, h.SeqNum, err)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	c.authed = true
	c.current = sess
	if err := c.sendPacket(krb.MsgAPRep, respPayload); err != nil {
		return false
	}
	log.Infof("[V] AP authentication accepted remote=%s client=%s seq=%d", c.remote, c.current.IDClient, h.SeqNum)
	return true
}

func (c *connectionState) handleAPPPacket(h krb.ProtocolHeader, payload []byte) bool {
	if !c.authed || c.current == nil {
		log.Warnf("[V] APP rejected without session remote=%s seq=%d", c.remote, h.SeqNum)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
		return false
	}
	if err := c.replay.Check(h.Timestamp, h.SeqNum); err != nil {
		log.Warnf("[V] APP replay check failed remote=%s client=%s seq=%d err=%v", c.remote, c.current.IDClient, h.SeqNum, err)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	respSeq := c.nextSeq()
	respType, respPayload, respErr := c.service.handleAPPReq(h, payload, c.current, c.sendPacketWithSeq, respSeq, c.nextSeq)
	if respErr != nil {
		log.Warnf("[V] APP handling failed remote=%s client=%s seq=%d err=%v", c.remote, c.current.IDClient, h.SeqNum, respErr)
		_ = c.sendPacketWithSeq(respType, respSeq, respPayload)
		return false
	}
	if err := c.sendPacketWithSeq(respType, respSeq, respPayload); err != nil {
		return false
	}
	if c.current != nil && c.current.Closed {
		log.Infof("[V] session closed remote=%s client=%s pty_session_id=%d", c.remote, c.current.IDClient, c.current.PtySessionID)
		return false
	}
	return respType == krb.MsgApp
}

func (c *connectionState) nextSeq() uint32 {
	seq := atomic.AddUint32(&c.sendSeq, 1)
	if seq == 0 {
		return atomic.AddUint32(&c.sendSeq, 1)
	}
	return seq
}

func (c *connectionState) sendPacket(msgType uint8, payload []byte) error {
	return c.sendPacketWithSeq(msgType, c.nextSeq(), payload)
}

func (c *connectionState) sendPacketWithSeq(msgType uint8, seq uint32, payload []byte) error {
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

func (c *connectionState) writeError(seq uint32, code int32) error {
	err := c.sendPacketWithSeq(krb.MsgErr, seq, krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[V] error response send failed seq=%d code=%d err=%v", seq, code, err)
		return err
	}
	log.Warnf("[V] error response sent seq=%d code=%d", seq, code)
	return nil
}

func (c *connectionState) close() {
	c.cancel()
	_ = c.conn.Close()
	log.Infof("[V] connection closed remote=%s", c.remote)
}
