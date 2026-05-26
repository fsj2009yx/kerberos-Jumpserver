package service

import (
	"fmt"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
	"security-project/verify_server/service/pty"
)

// handleAPPReq 处理来自客户端的APP_REQ消息，解析请求内容，验证请求合法性，
// 并根据请求的操作类型执行相应的PTY操作，如打开PTY会话、发送输入、调整窗口大小、发送信号或关闭PTY会话等
func (s *Service) handleAPPReq(h krb.ProtocolHeader, payload []byte, current *SessionContext, sendPacket func(uint8, uint32, []byte) error, respSeq uint32, nextSeq func() uint32) (uint8, []byte, error) {
	req, err := krb.ParseAPPReqPayload(payload)
	if err != nil {
		log.Warnf("[V] parse APP_REQ failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		s.appendAudit(AuditRecord{
			Kind:         "pty",
			EventType:    "APP_REQ",
			SessionID:    auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:     current.IDClient,
			ClientIP:     current.ClientIP,
			ADc:          current.ADc,
			PTYSessionID: current.PtySessionID,
			Direction:    "C->V",
			SeqNum:       h.SeqNum,
			MsgType:      h.MsgType,
			Result:       "fail",
			ErrorCode:    krb.CodeName(krb.CodeFromError(err)),
		})
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}

	// 验证请求中的客户端ID是否与当前会话的客户端ID匹配，如果不匹配则返回错误，防止客户端冒用其他会话的身份进行操作
	if req.IDClient.Len > 0 && string(req.IDClient.Data) != current.IDClient {
		err := krb.ErrorFromCode(krb.ErrCertIDMismatch)
		log.Warnf("[V] APP client mismatch session_client=%s req_client=%s", current.IDClient, string(req.IDClient.Data))
		s.appendAudit(AuditRecord{
			Kind:         "pty",
			EventType:    "APP_REQ",
			SessionID:    auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:     current.IDClient,
			ClientIP:     current.ClientIP,
			ADc:          current.ADc,
			PTYSessionID: current.PtySessionID,
			Direction:    "C->V",
			SeqNum:       h.SeqNum,
			MsgType:      h.MsgType,
			Result:       "fail",
			ErrorCode:    krb.CodeName(krb.ErrCertIDMismatch),
		})
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertIDMismatch), err
	}

	// 验证当前会话是否已经过期，如果当前时间超过了会话的ExpireAt时间戳，则认为会话已经过期，返回错误并拒绝处理请求
	if uint32(time.Now().Unix()) > current.ExpireAt {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		log.Warnf("[V] APP rejected expired session client=%s expire_at=%d", current.IDClient, current.ExpireAt)
		s.appendAudit(AuditRecord{
			Kind:         "pty",
			EventType:    "APP_REQ",
			SessionID:    auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:     current.IDClient,
			ClientIP:     current.ClientIP,
			ADc:          current.ADc,
			PTYSessionID: current.PtySessionID,
			Direction:    "C->V",
			SeqNum:       h.SeqNum,
			MsgType:      h.MsgType,
			Result:       "fail",
			ErrorCode:    krb.CodeName(krb.ErrTicketExpired),
		})
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	// 如果当前会话关联了客户端证书，则使用证书中的RSA公钥验证请求中的签名，确保请求的真实性和完整性，防止请求被篡改或伪造
	cert := s.clientCerts[current.IDClient]
	if cert == nil {
		err := krb.ErrorFromCode(krb.ErrCertLoadFail)
		log.Warnf("[V] client cert missing for APP_REQ client=%s", current.IDClient)
		s.appendAudit(AuditRecord{
			Kind:            "pty",
			EventType:       "APP_REQ",
			SessionID:       auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:        current.IDClient,
			ClientIP:        current.ClientIP,
			ADc:             current.ADc,
			PTYSessionID:    current.PtySessionID,
			Direction:       "C->V",
			SeqNum:          h.SeqNum,
			MsgType:         h.MsgType,
			Result:          "fail",
			ErrorCode:       krb.CodeName(krb.ErrCertLoadFail),
			RSAVerifyResult: "fail",
		})
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertLoadFail), err
	}
	pub, err := cert.PublicKeyRSA()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrCertSigInvalid)
		log.Warnf("[V] cert public key parse failed client=%s err=%v", current.IDClient, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertSigInvalid), err
	}
	if err := krb.VerifyCipherSignature(h.SeqNum, req.Cipher, req.RSASignC, pub); err != nil {
		log.Warnf("[V] APP signature verify failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		s.appendAudit(AuditRecord{
			Kind:            "pty",
			EventType:       "APP_REQ",
			SessionID:       auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:        current.IDClient,
			ClientIP:        current.ClientIP,
			ADc:             current.ADc,
			PTYSessionID:    current.PtySessionID,
			Direction:       "C->V",
			SeqNum:          h.SeqNum,
			MsgType:         h.MsgType,
			Result:          "fail",
			ErrorCode:       krb.CodeName(krb.CodeFromError(err)),
			RSAVerifyResult: "fail",
		})
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}

	plain, err := krb.DecryptAPPReqPlain(req.Cipher, current.KeyCV)
	if err != nil {
		log.Warnf("[V] APP decrypt failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		s.appendAudit(AuditRecord{
			Kind:            "pty",
			EventType:       "APP_REQ",
			SessionID:       auditSessionID(current.IDClient, current.PtySessionID),
			ClientID:        current.IDClient,
			ClientIP:        current.ClientIP,
			ADc:             current.ADc,
			PTYSessionID:    current.PtySessionID,
			Direction:       "C->V",
			SeqNum:          h.SeqNum,
			MsgType:         h.MsgType,
			Result:          "fail",
			ErrorCode:       krb.CodeName(krb.CodeFromError(err)),
			RSAVerifyResult: "ok",
		})
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("decrypt failed")), err
	}
	// 每处理一条APP请求，无论请求的具体操作类型如何，都会将当前会话的TotalFrames计数器和服务端的ptyFrames计数器都增加1，并更新当前会话的LastIO时间戳为当前时间
	//这些统计信息可以帮助服务端监控每个会话的活跃程度和总的PTY交互量。
	atomic.AddUint64(&current.TotalFrames, 1)

	// 服务端的ptyFrames计数器是一个全局统计量，用于记录所有会话中处理的PTY相关请求的总数。
	//每当处理一条APP请求时，无论请求的具体操作类型如何，都会将这个计数器增加1，以反映服务端处理的PTY交互的总量。
	atomic.AddUint64(&s.ptyFrames, 1)
	current.LastIO = time.Now()
	log.Infof("[V] APP_REQ received client=%s seq=%d op=%d pty_session_id=%d payload_bytes=%d", current.IDClient, h.SeqNum, plain.PtyOp, plain.PtySessionID, len(plain.Payload))
	auditTargetID := current.TargetID
	auditTargetHost := current.TargetHost
	auditSSHUser := current.SSHUser
	if plain.PtyOp == pty.OpOpenSSH {
		if targetID, _, _, _, parseErr := pty.ParseOpenSSHPayload(plain.Payload); parseErr == nil {
			auditTargetID = targetID
			if target, lookupErr := s.lookupSSHTarget(targetID); lookupErr == nil {
				auditTargetHost = fmt.Sprintf("%s:%d", target.Host, target.Port)
				auditSSHUser = target.SSHUser
			}
		}
	}

	// 无论APP请求的处理结果如何，服务端都会将该请求的相关信息记录到审计日志中
	//包括请求的操作类型、会话ID、客户端ID、客户端IP、目标信息、SSH用户、PTY会话ID、请求方向、序列号、消息类型、操作结果等。这些审计记录可以帮助服务端追踪每个请求的处理情况和结果，便于后续的安全分析和问题排查。
	s.appendAudit(AuditRecord{
		Kind:            "pty",
		EventType:       "APP_REQ",
		SessionID:       auditSessionID(current.IDClient, plain.PtySessionID),
		ClientID:        current.IDClient,
		ClientIP:        current.ClientIP,
		ADc:             current.ADc,
		TargetID:        auditTargetID,
		TargetHost:      auditTargetHost,
		SSHUser:         auditSSHUser,
		PTYSessionID:    plain.PtySessionID,
		Direction:       "C->V",
		SeqNum:          h.SeqNum,
		MsgType:         h.MsgType,
		PTYOp:           plain.PtyOp,
		FrameType:       auditPTYOpName(plain.PtyOp),
		FrameSize:       len(plain.Payload),
		PayloadB64:      auditPayload(plain.Payload),
		Result:          "ok",
		RSAVerifyResult: "ok",
	})

	switch plain.PtyOp {
	case pty.OpOpenSSH:
		targetID, term, cols, rows, err := pty.ParseOpenSSHPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] ssh open payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad ssh open payload")), err
		}
		if term == "" {
			term = s.Config.PTYDefaultTerm
		}
		target, err := s.lookupSSHTarget(targetID)
		if err != nil {
			log.Warnf("[V] ssh target lookup failed client=%s target=%s err=%v", current.IDClient, targetID, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh target not found")), err
		}
		if err := checkTargetPermission(current.IDClient, target); err != nil {
			log.Warnf("[V] ssh target permission denied client=%s target=%s err=%v", current.IDClient, targetID, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh target denied")), err
		}
		if current.PTY != nil {
			s.cleanupPTY(current, "replace ssh pty")
		}
		sshSession, startErr := pty.StartSSHSession(target, term, cols, rows)
		if startErr != nil || sshSession == nil {
			if startErr == nil {
				startErr = krb.ErrorFromCode(krb.ErrSessionNotFound)
			}
			log.Errorf("[V] ssh pty start failed client=%s target=%s host=%s:%d user=%s term=%s cols=%d rows=%d err=%v", current.IDClient, target.ID, target.Host, target.Port, target.SSHUser, term, cols, rows, startErr)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh pty start failed")), startErr
		}
		s.resetPTYContext(current)
		current.PTY = sshSession
		current.PtySessionID = s.nextSessionID()
		current.TargetID = target.ID
		current.TargetHost = fmt.Sprintf("%s:%d", target.Host, target.Port)
		current.SSHUser = target.SSHUser
		current.Closed.Store(false)
		if current.Cancel != nil {
			go func(sess *SessionContext) {
				<-sess.Ctx.Done()
				if sess.PTY != nil {
					_ = sess.PTY.Close()
				}
			}(current)
		}
		go pty.StreamOutput(current.PTY, pty.StreamCallbacks{
			ClientID:   current.IDClient,
			SessionID:  current.PtySessionID,
			Done:       current.Ctx.Done(),
			NextSeq:    nextSeq,
			SendPacket: sendPacket,
			BuildPayload: func(seq uint32, event uint8, sessionID uint32, exitCode int32, payload []byte) []byte {
				return s.buildAPPRep(current, seq, event, sessionID, exitCode, payload)
			},
			OnFrame: func() {
				atomic.AddUint64(&current.TotalFrames, 1)
				atomic.AddUint64(&s.ptyFrames, 1)
			},
			OnIO: func(at time.Time) {
				current.LastIO = at
			},
			IsClosed: func() bool {
				return current.Closed.Load()
			},
		})
		out := []byte(fmt.Sprintf("ssh open ok: %s -> %s", current.IDClient, current.TargetID))
		log.Infof("[V] ssh pty opened client=%s target=%s host=%s user=%s pty_session_id=%d term=%s cols=%d rows=%d", current.IDClient, current.TargetID, current.TargetHost, current.SSHUser, current.PtySessionID, term, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventOpenOK, current.PtySessionID, -1, out), nil
	case pty.OpInput:
		if current.PTY == nil {
			log.Warnf("[V] pty input rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		if _, err := current.PTY.Write(plain.Payload); err != nil {
			log.Warnf("[V] pty input write failed client=%s payload_bytes=%d err=%v", current.IDClient, len(plain.Payload), err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty write failed")), krb.ErrorFromCode(krb.ErrSocketSend)
		}
		out := []byte{}
		log.Infof("[V] pty input accepted client=%s pty_session_id=%d payload_bytes=%d", current.IDClient, current.PtySessionID, len(plain.Payload))
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventOutput, current.PtySessionID, -1, out), nil
	case pty.OpResize:
		if current.PTY == nil {
			log.Warnf("[V] pty resize rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		cols, rows, err := pty.ParseResizePayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] pty resize payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad resize payload")), err
		}
		if err := current.PTY.Resize(cols, rows); err != nil {
			log.Warnf("[V] pty resize failed client=%s cols=%d rows=%d err=%v", current.IDClient, cols, rows, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("resize failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Infof("[V] pty resized client=%s pty_session_id=%d cols=%d rows=%d", current.IDClient, current.PtySessionID, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventOutput, current.PtySessionID, -1, []byte("")), nil
	case pty.OpSignal:
		if current.PTY == nil {
			log.Warnf("[V] pty signal rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		sig, err := pty.ParseSignalPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] pty signal payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad signal payload")), err
		}
		if err := current.PTY.Signal(sig); err != nil {
			log.Warnf("[V] pty signal failed client=%s signal=%d err=%v", current.IDClient, sig, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("signal failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Infof("[V] pty signal sent client=%s pty_session_id=%d signal=%d", current.IDClient, current.PtySessionID, sig)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventOutput, current.PtySessionID, -1, []byte("signal ok")), nil
	case pty.OpClose:
		ptySessionID := current.PtySessionID
		resp := s.buildAPPRep(current, respSeq, pty.EventExit, ptySessionID, 0, []byte("bye"))
		s.cleanupPTY(current, "pty close")
		log.Infof("[V] pty session closed client=%s pty_session_id=%d total_frames=%d", current.IDClient, ptySessionID, atomic.LoadUint64(&current.TotalFrames))
		return krb.MsgApp, resp, nil
	default:
		log.Warnf("[V] invalid pty operation client=%s op=%d", current.IDClient, plain.PtyOp)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, pty.EventError, current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrorFromCode(krb.ErrMsgTypeInvalid)
	}
}

// handleAppPacket 处理来自客户端的APP消息，首先检查会话是否已经认证和存在，如果未认证或会话不存在，则拒绝处理并返回错误；
func (s *Service) handleAppPacket(c *ConnState, h krb.ProtocolHeader, payload []byte) bool {

	// 如果当前连接的会话上下文为nil，说明该连接尚未绑定到任何会话，此时服务端会尝试从APP请求的payload中解析出客户端ID
	//并根据客户端ID查找对应的会话，如果找到有效的会话且未过期，则将该连接绑定到该会话，并标记为已认证和已绑定
	//如果解析失败、客户端ID缺失、会话不存在或会话过期，则拒绝处理请求并返回相应的错误信息
	if c.current == nil {
		req, err := krb.ParseAPPReqPayload(payload)
		if err != nil {
			log.Warnf("[V] APP rejected before bind parse failed remote=%s seq=%d err=%v", c.remote, h.SeqNum, err)
			_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
			return false
		}
		clientID := string(req.IDClient.Data)
		if clientID == "" {
			log.Warnf("[V] APP rejected without client id remote=%s seq=%d", c.remote, h.SeqNum)
			_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
			return false
		}
		s.state.mu.RLock()
		sess := s.state.Sessions[clientID]
		s.state.mu.RUnlock()
		if sess == nil {
			log.Warnf("[V] APP rejected no Kerberos session remote=%s client=%s seq=%d", c.remote, clientID, h.SeqNum)
			_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
			return false
		}
		if uint32(time.Now().Unix()) > sess.ExpireAt {
			log.Warnf("[V] APP rejected expired Kerberos session remote=%s client=%s expire_at=%d seq=%d", c.remote, clientID, sess.ExpireAt, h.SeqNum)
			s.cleanupSession(sess, "expired app bind")
			_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired))
			return false
		}
		sess.ClientIP = c.remote
		c.current = sess
		c.authed = true
		c.appBound = true
		log.Infof("[V] APP connection bound remote=%s client=%s seq=%d", c.remote, clientID, h.SeqNum)
	}
	if !c.authed {
		log.Warnf("[V] APP rejected without authenticated binding remote=%s seq=%d", c.remote, h.SeqNum)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
		return false
	}
	if c.current.AppReplay == nil {
		c.current.AppReplay = krb.NewReplayWindow(s.Config.AntiReplayWindow)
	}
	if err := c.current.AppReplay.Check(h.Timestamp, h.SeqNum); err != nil {
		log.Warnf("[V] APP replay check failed remote=%s client=%s seq=%d err=%v", c.remote, c.current.IDClient, h.SeqNum, err)
		_ = c.sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
		return false
	}
	c.appBound = true
	respSeq := c.nextSeq()
	respType, respPayload, respErr := s.handleAPPReq(h, payload, c.current, c.sendPacketWithSeq, respSeq, c.nextSeq)
	if respErr != nil {
		log.Warnf("[V] APP handling failed remote=%s client=%s seq=%d err=%v", c.remote, c.current.IDClient, h.SeqNum, respErr)
		_ = c.sendPacketWithSeq(respType, respSeq, respPayload)
		return false
	}
	if err := c.sendPacketWithSeq(respType, respSeq, respPayload); err != nil {
		return false
	}
	if c.current != nil && c.current.Closed.Load() {
		log.Infof("[V] session closed remote=%s client=%s pty_session_id=%d", c.remote, c.current.IDClient, c.current.PtySessionID)
		return false
	}
	return respType == krb.MsgApp
}

func (s *Service) buildAPPRep(current *SessionContext, seq uint32, event uint8, ptySessionID uint32, exitCode int32, payload []byte) []byte {
	//构建回调Sign函数
	signFn := func(cipherData []byte) ([256]byte, error) {
		raw := make([]byte, 4+len(cipherData))
		copy(raw[:4], krb.Uint32ToBytes(seq))
		copy(raw[4:], cipherData)
		return krb.SignSHA256(raw, s.privKey)
	}
	wire, err := krb.BuildAPPRepPayload(event, ptySessionID, exitCode, payload, current.KeyCV, signFn)
	if err != nil {
		log.Errorf("[V] build APP_REP failed client=%s seq=%d event=%d err=%v", current.IDClient, seq, event, err)
		return wire
	}
	s.appendAudit(AuditRecord{
		Kind:         "pty",
		EventType:    "APP_REP",
		SessionID:    auditSessionID(current.IDClient, ptySessionID),
		ClientID:     current.IDClient,
		ClientIP:     current.ClientIP,
		ADc:          current.ADc,
		TargetID:     current.TargetID,
		TargetHost:   current.TargetHost,
		SSHUser:      current.SSHUser,
		PTYSessionID: ptySessionID,
		Direction:    "V->C",
		SeqNum:       seq,
		MsgType:      krb.MsgApp,
		PTYEvent:     event,
		FrameType:    auditPTYEventName(event),
		FrameSize:    len(payload),
		PayloadB64:   auditPayload(payload),
		ExitCode:     exitCode,
		Result:       "ok",
	})
	return wire
}
