package service

import (
	"context"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

func (s *Service) handleAPReq(connCtx context.Context, h krb.ProtocolHeader, payload []byte, sendPacket func(uint8, []byte) error) ([]byte, *SessionContext, error) {
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

	sess := &SessionContext{
		IDClient:     clientID,
		ADc:          ticket.ADc,
		KeyCV:        ticket.KeyCV,
		ExpireAt:     ticket.TS4 + ticket.Lifetime,
		PtySessionID: 0,
		LastIO:       time.Now(),
	}
	sess.Ctx, sess.Cancel = context.WithCancel(connCtx)
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
