package service

import (
	"context"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

func (s *Service) handleAPReq(connCtx context.Context, h krb.ProtocolHeader, payload []byte) ([]byte, *SessionContext, error) {
	req, err := krb.ParseAPReqPayload(payload)
	if err != nil {
		log.Warnf("[V] parse AP_REQ failed seq=%d err=%v", h.SeqNum, err)
		return nil, nil, err
	}
	ticket, err := krb.DecodeTicketV(req.TicketV, s.state.Kv)
	if err != nil {
		log.Warnf("[V] decode service ticket failed seq=%d err=%v", h.SeqNum, err)
		return nil, nil, err
	}
	clientID := string(ticket.IDClient.Data)
	if ticket.IDV.Len > 0 && string(ticket.IDV.Data) != s.state.IDV {
		log.Warnf("[V] invalid service ticket id_v=%s expected=%s client=%s", string(ticket.IDV.Data), s.state.IDV, clientID)
		return nil, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	if uint32(time.Now().Unix()) > ticket.TS4+ticket.Lifetime {
		log.Warnf("[V] service ticket expired client=%s expire=%d", clientID, ticket.TS4+ticket.Lifetime)
		return nil, nil, krb.ErrorFromCode(krb.ErrTicketExpired)
	}
	auth, err := krb.DecodeAuthenticatorCV(req.AuthCipher, ticket.KeyCV)
	if err != nil {
		log.Warnf("[V] decode AP authenticator failed client=%s err=%v", clientID, err)
		return nil, nil, err
	}
	if string(auth.IDClient.Data) != clientID {
		log.Warnf("[V] auth mismatch auth_client=%s ticket_client=%s", string(auth.IDClient.Data), clientID)
		return nil, nil, krb.ErrorFromCode(krb.ErrAuthMismatch)
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc {
		log.Warnf("[V] address mismatch client=%s auth_adc=%d ticket_adc=%d", clientID, auth.ADc, ticket.ADc)
		return nil, nil, krb.ErrorFromCode(krb.ErrADMismatch)
	}

	//Kerberos V5 AP-REQ is valid, create session context for this client
	//当Kerberos V5 AP-REQ有效时，为该客户端创建会话上下文

	sess := &SessionContext{
		IDClient:     clientID,
		ADc:          ticket.ADc,
		KeyCV:        ticket.KeyCV,
		ExpireAt:     ticket.TS4 + ticket.Lifetime,
		PtySessionID: 0,
		LastIO:       time.Now(),
		AppReplay:    krb.NewReplayWindow(s.Config.AntiReplayWindow),
	}

	// 使用AP-REQ消息的上下文作为会话上下文的基础，并将其存储在服务端的会话管理器中，以便后续的消息处理能够关联到正确的客户端会话
	sess.Ctx, sess.Cancel = context.WithCancel(context.Background())
	s.state.mu.Lock()
	s.state.Sessions[sess.IDClient] = sess
	s.state.mu.Unlock()
	log.Infof("[V] session created client=%s expire_at=%d adc=%d", sess.IDClient, sess.ExpireAt, sess.ADc)

	resp, err := krb.BuildAPRepPayload(auth.TS5, ticket.KeyCV)
	if err != nil {
		log.Warnf("[V] build AP_REP failed client=%s err=%v", sess.IDClient, err)
		return nil, nil, err
	}
	return resp, sess, nil
}

func (s *Service) handleAPReqPacket(c *ConnState, h krb.ProtocolHeader, payload []byte) bool {

	// AP_REQ消息必须是未认证状态下的第一个消息，因此如果连接已经认证过了，就说明收到了重复的AP_REQ消息，可能是重放攻击或者客户端错误
	if c.authed {
		log.Warnf("[V] duplicate AP_REQ remote=%s seq=%d", c.remote, h.SeqNum)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
		return false
	}

	// 对AP_REQ消息进行重放攻击检查，检查的依据是消息的时间戳和序列号，如果消息的时间戳过旧或者序列号已经出现过了，就说明可能是重放攻击
	if err := c.replay.Check(h.Timestamp, h.SeqNum); err != nil {
		log.Warnf("[V] AP replay check failed remote=%s seq=%d err=%v", c.remote, h.SeqNum, err)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	respPayload, sess, err := s.handleAPReq(c.ctx, h, payload)
	if err != nil {
		log.Warnf("[V] AP_REQ handling failed remote=%s seq=%d err=%v", c.remote, h.SeqNum, err)
		code := krb.CodeFromError(err)
		s.appendAudit(AuditRecord{
			Kind:      "auth",
			EventType: "AP_REQ",
			ClientIP:  c.remote,
			SeqNum:    h.SeqNum,
			MsgType:   h.MsgType,
			Result:    "fail",
			ErrorCode: krb.CodeName(code),
		})
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	c.authed = true
	sess.ClientIP = c.remote
	c.current = sess
	if err := c.sendPacket(krb.MsgAPRep, respPayload); err != nil {
		return false
	}
	log.Infof("[V] AP authentication accepted remote=%s client=%s seq=%d", c.remote, c.current.IDClient, h.SeqNum)
	s.appendAudit(AuditRecord{
		Kind:         "auth",
		EventType:    "AP_REQ",
		SessionID:    auditSessionID(sess.IDClient, 0),
		ClientID:     sess.IDClient,
		ClientIP:     c.remote,
		ADc:          sess.ADc,
		SeqNum:       h.SeqNum,
		MsgType:      h.MsgType,
		Result:       "ok",
		FrameType:    "ap_auth",
		PayloadB64:   auditPayload(payload),
		FrameSize:    len(payload),
		ErrorCode:    "",
		PTYSessionID: sess.PtySessionID,
	})
	return true
}
