package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/golib/log"

	"security-project/common/crypto"
	"security-project/common/krb"
	"security-project/verify_server/config"
)

const (
	ptyEventOpenOK = 0x11
	ptyEventOutput = 0x12
	ptyEventExit   = 0x13
	ptyEventError  = 0x14

	ptyOpOpen   = 0x01
	ptyOpInput  = 0x02
	ptyOpResize = 0x03
	ptyOpSignal = 0x04
	ptyOpClose  = 0x05
)

type Service struct {
	Config      *config.Config
	state       *VState
	startTime   time.Time
	nextPtyID   uint32
	ptyFrames   uint64
	privKey     *crypto.RSAKey
	clientCerts map[string]*krb.Certificate
	httpServer  *http.Server
}

func NewService(configPath string) *Service {
	log.Infof("[V] initializing service config=%s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Errorf("[V] load config failed err=%v", err)
		panic(fmt.Sprintf("load config: %v", err))
	}
	kv, err := krb.LoadConfiguredKey8(cfg.KVPath, cfg.KVHex, "v k_v")
	if err != nil {
		log.Errorf("[V] load k_v failed err=%v", err)
		panic(fmt.Sprintf("load k_v: %v", err))
	}
	priv, err := krb.LoadRSAPrivateKey(cfg.PrivKeyPath)
	if err != nil {
		log.Errorf("[V] load private key failed path=%s err=%v", cfg.PrivKeyPath, err)
		panic(fmt.Sprintf("load private key: %v", err))
	}
	s := &Service{
		Config:      cfg,
		state:       &VState{IDV: cfg.NodeID, Kv: kv, Sessions: make(map[string]*SessionContext)},
		startTime:   time.Now(),
		privKey:     priv,
		clientCerts: make(map[string]*krb.Certificate),
	}
	for _, item := range cfg.ClientDB {
		if item.CertPath == "" {
			continue
		}
		cert, err := krb.CertLoad(item.CertPath)
		if err != nil {
			log.Warnf("[V] client cert load failed client=%s path=%s err=%v", item.ID, item.CertPath, err)
			continue
		}
		s.clientCerts[item.ID] = cert
		log.Infof("[V] client cert loaded client=%s path=%s", item.ID, item.CertPath)
	}
	log.Infof("[V] service initialized node_id=%s clients=%d certs=%d pty_shell=%s", cfg.NodeID, len(cfg.ClientDB), len(s.clientCerts), cfg.PTYShell)
	return s
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		log.Infof("[V] starting webui addr=%s:%d", s.Config.WebUIHost, s.Config.WebUIPort)
		go s.runWebUI()
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("[V] listen failed addr=%s err=%v", addr, err)
		return err
	}
	defer ln.Close()
	log.Infof("[V] listening addr=%s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorf("[V] accept failed err=%v", err)
			continue
		}
		log.Infof("[V] accepted connection remote=%s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *Service) nextSessionID() uint32 {
	return atomic.AddUint32(&s.nextPtyID, 1)
}

func (s *Service) handleConnection(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	replay := krb.NewReplayWindow(s.Config.AntiReplayWindow)
	var sendSeq uint32
	nextConnSeq := func() uint32 {
		seq := atomic.AddUint32(&sendSeq, 1)
		if seq == 0 {
			return atomic.AddUint32(&sendSeq, 1)
		}
		return seq
	}
	defer func() {
		_ = conn.Close()
		log.Infof("[V] connection closed remote=%s", remote)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writeMu sync.Mutex
	sendPacketWithSeq := func(msgType uint8, seq uint32, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		err := krb.WritePacket(conn, msgType, seq, uint32(time.Now().Unix()), payload)
		if err != nil {
			log.Errorf("[V] packet send failed remote=%s msg_type=%d seq=%d err=%v", remote, msgType, seq, err)
			return err
		}
		log.Infof("[V] packet sent remote=%s msg_type=%d seq=%d payload_bytes=%d", remote, msgType, seq, len(payload))
		return nil
	}
	sendPacket := func(msgType uint8, payload []byte) error {
		return sendPacketWithSeq(msgType, nextConnSeq(), payload)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var authed bool
	var current *SessionContext
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadTimeoutSec) * time.Second))
		h, payload, err := krb.ReadPacket(conn, s.Config.MaxPayloadBytes)
		if err != nil {
			code := krb.CodeFromError(err)
			if code != krb.ErrSocketRecv {
				log.Warnf("[V] read packet failed remote=%s code=%d err=%v", remote, code, err)
				_ = s.writeError(conn, nextConnSeq(), code)
			}
			return
		}
		log.Infof("[V] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d authed=%t", remote, h.MsgType, h.SeqNum, len(payload), authed)
		switch h.MsgType {
		case krb.MsgAPReq:
			if authed {
				log.Warnf("[V] duplicate AP_REQ remote=%s seq=%d", remote, h.SeqNum)
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
				return
			}
			if err := replay.Check(h.Timestamp, h.SeqNum); err != nil {
				log.Warnf("[V] AP replay check failed remote=%s seq=%d err=%v", remote, h.SeqNum, err)
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
				return
			}
			respPayload, sess, err := s.handleAPReq(ctx, h, payload, sendPacket)
			if err != nil {
				log.Warnf("[V] AP_REQ handling failed remote=%s seq=%d err=%v", remote, h.SeqNum, err)
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
				return
			}
			authed = true
			current = sess
			if err := sendPacket(krb.MsgAPRep, respPayload); err != nil {
				return
			}
			log.Infof("[V] AP authentication accepted remote=%s client=%s seq=%d", remote, current.IDClient, h.SeqNum)
		case krb.MsgApp:
			if !authed || current == nil {
				log.Warnf("[V] APP rejected without session remote=%s seq=%d", remote, h.SeqNum)
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound))
				return
			}
			if err := replay.Check(h.Timestamp, h.SeqNum); err != nil {
				log.Warnf("[V] APP replay check failed remote=%s client=%s seq=%d err=%v", remote, current.IDClient, h.SeqNum, err)
				_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)))
				return
			}
			respSeq := nextConnSeq()
			respType, respPayload, respErr := s.handleAPPReq(h, payload, current, sendPacketWithSeq, respSeq, nextConnSeq)
			if respErr != nil {
				log.Warnf("[V] APP handling failed remote=%s client=%s seq=%d err=%v", remote, current.IDClient, h.SeqNum, respErr)
				_ = sendPacketWithSeq(respType, respSeq, respPayload)
				return
			}
			if err := sendPacketWithSeq(respType, respSeq, respPayload); err != nil {
				return
			}
			if current != nil && current.Closed {
				log.Infof("[V] session closed remote=%s client=%s pty_session_id=%d", remote, current.IDClient, current.PtySessionID)
				return
			}
			if respType == krb.MsgApp {
				continue
			}
			return
		default:
			log.Warnf("[V] invalid message type remote=%s msg_type=%d seq=%d", remote, h.MsgType, h.SeqNum)
			_ = sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid))
			return
		}
	}
}

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

func (s *Service) handleAPPReq(h krb.ProtocolHeader, payload []byte, current *SessionContext, sendPacket func(uint8, uint32, []byte) error, respSeq uint32, nextSeq func() uint32) (uint8, []byte, error) {
	req, err := krb.ParseAPPReqPayload(payload)
	if err != nil {
		log.Warnf("[V] parse APP_REQ failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if req.IDClient.Len > 0 && string(req.IDClient.Data) != current.IDClient {
		err := krb.ErrorFromCode(krb.ErrCertIDMismatch)
		log.Warnf("[V] APP client mismatch session_client=%s req_client=%s", current.IDClient, string(req.IDClient.Data))
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertIDMismatch), err
	}
	if uint32(time.Now().Unix()) > current.ExpireAt {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		log.Warnf("[V] APP rejected expired session client=%s expire_at=%d", current.IDClient, current.ExpireAt)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	if cert := s.clientCerts[current.IDClient]; cert != nil {
		pub, err := cert.PublicKeyRSA()
		if err != nil {
			err := krb.ErrorFromCode(krb.ErrCertSigInvalid)
			log.Warnf("[V] cert public key parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertSigInvalid), err
		}
		if err := krb.VerifyCipherSignature(h.SeqNum, req.Cipher, req.RSASignC, pub); err != nil {
			log.Warnf("[V] APP signature verify failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
			return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
		}
	}

	plain, err := krb.DecryptAPPReqPlain(req.Cipher, current.KeyCV)
	if err != nil {
		log.Warnf("[V] APP decrypt failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("decrypt failed")), err
	}
	atomic.AddUint64(&current.TotalFrames, 1)
	atomic.AddUint64(&s.ptyFrames, 1)
	current.LastIO = time.Now()
	log.Infof("[V] APP_REQ received client=%s seq=%d op=%d pty_session_id=%d payload_bytes=%d", current.IDClient, h.SeqNum, plain.PtyOp, plain.PtySessionID, len(plain.Payload))

	switch plain.PtyOp {
	case ptyOpOpen:
		term, cols, rows, err := parsePtyOpenPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] pty open payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad open payload")), err
		}
		if term == "" {
			term = s.Config.PTYDefaultTerm
		}
		if current.PTY != nil {
			if err := current.PTY.Close(); err != nil {
				log.Warnf("[V] previous pty close returned error client=%s err=%v", current.IDClient, err)
			}
		}
		ptySession, startErr := startPTYSession(s.Config.PTYShell, term, cols, rows)
		if startErr != nil || ptySession == nil {
			if startErr == nil {
				startErr = krb.ErrorFromCode(krb.ErrSessionNotFound)
			}
			log.Errorf("[V] pty start failed client=%s shell=%s term=%s cols=%d rows=%d err=%v", current.IDClient, s.Config.PTYShell, term, cols, rows, startErr)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty start failed")), startErr
		}
		current.PTY = ptySession
		current.PtySessionID = s.nextSessionID()
		if current.Cancel != nil {
			go func(sess *SessionContext) {
				<-sess.Ctx.Done()
				if sess.PTY != nil {
					_ = sess.PTY.Close()
				}
			}(current)
		}
		go s.streamPTYOutput(current, sendPacket, nextSeq)
		out := []byte(fmt.Sprintf("open ok: %s", current.IDClient))
		log.Infof("[V] pty opened client=%s pty_session_id=%d term=%s cols=%d rows=%d", current.IDClient, current.PtySessionID, term, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOpenOK, current.PtySessionID, -1, out), nil
	case ptyOpInput:
		if current.PTY == nil {
			log.Warnf("[V] pty input rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		if _, err := current.PTY.PTY.Write(plain.Payload); err != nil {
			log.Warnf("[V] pty input write failed client=%s payload_bytes=%d err=%v", current.IDClient, len(plain.Payload), err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty write failed")), krb.ErrorFromCode(krb.ErrSocketSend)
		}
		out := []byte{}
		log.Infof("[V] pty input accepted client=%s pty_session_id=%d payload_bytes=%d", current.IDClient, current.PtySessionID, len(plain.Payload))
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, out), nil
	case ptyOpResize:
		if current.PTY == nil {
			log.Warnf("[V] pty resize rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		cols, rows, err := parsePtyResizePayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] pty resize payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad resize payload")), err
		}
		if err := current.PTY.Resize(cols, rows); err != nil {
			log.Warnf("[V] pty resize failed client=%s cols=%d rows=%d err=%v", current.IDClient, cols, rows, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("resize failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Infof("[V] pty resized client=%s pty_session_id=%d cols=%d rows=%d", current.IDClient, current.PtySessionID, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, []byte("")), nil
		// return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, []byte("resize ok")), nil
	case ptyOpSignal:
		if current.PTY == nil {
			log.Warnf("[V] pty signal rejected not open client=%s", current.IDClient)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		sig, err := parsePtySignalPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] pty signal payload parse failed client=%s err=%v", current.IDClient, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad signal payload")), err
		}
		if err := current.PTY.Signal(sig); err != nil {
			log.Warnf("[V] pty signal failed client=%s signal=%d err=%v", current.IDClient, sig, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("signal failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Infof("[V] pty signal sent client=%s pty_session_id=%d signal=%d", current.IDClient, current.PtySessionID, sig)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, []byte("signal ok")), nil
	case ptyOpClose:
		if current.Cancel != nil {
			current.Cancel()
		}
		if current.PTY != nil {
			if err := current.PTY.Close(); err != nil {
				log.Warnf("[V] pty close returned error client=%s err=%v", current.IDClient, err)
			}
		}
		s.state.mu.Lock()
		delete(s.state.Sessions, current.IDClient)
		s.state.mu.Unlock()
		current.Closed = true
		log.Infof("[V] pty session closed client=%s pty_session_id=%d total_frames=%d", current.IDClient, current.PtySessionID, atomic.LoadUint64(&current.TotalFrames))
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventExit, current.PtySessionID, 0, []byte("bye")), nil
	default:
		log.Warnf("[V] invalid pty operation client=%s op=%d", current.IDClient, plain.PtyOp)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrorFromCode(krb.ErrMsgTypeInvalid)
	}
}

func (s *Service) streamPTYOutput(current *SessionContext, sendPacket func(uint8, uint32, []byte) error, nextSeq func() uint32) {
	if current == nil || current.PTY == nil || current.Ctx == nil {
		log.Warnf("[V] pty output stream skipped due to invalid session")
		return
	}
	log.Infof("[V] pty output stream started client=%s pty_session_id=%d", current.IDClient, current.PtySessionID)
	ch := make(chan []byte, 16)
	go current.PTY.ReadAll(ch, current.Ctx.Done())
	for data := range ch {
		if len(data) == 0 {
			continue
		}
		atomic.AddUint64(&current.TotalFrames, 1)
		atomic.AddUint64(&s.ptyFrames, 1)
		current.LastIO = time.Now()
		seq := nextSeq()
		rep := s.buildAPPRep(current, seq, ptyEventOutput, current.PtySessionID, -1, data)
		if err := sendPacket(krb.MsgApp, seq, rep); err != nil {
			log.Warnf("[V] pty output send failed client=%s seq=%d err=%v", current.IDClient, seq, err)
			return
		}
	}
	if current.Closed {
		log.Infof("[V] pty output stream ended after close client=%s", current.IDClient)
		return
	}
	seq := nextSeq()
	rep := s.buildAPPRep(current, seq, ptyEventExit, current.PtySessionID, 0, nil)
	if err := sendPacket(krb.MsgApp, seq, rep); err != nil {
		log.Warnf("[V] pty exit send failed client=%s seq=%d err=%v", current.IDClient, seq, err)
		return
	}
	log.Infof("[V] pty output stream ended client=%s pty_session_id=%d", current.IDClient, current.PtySessionID)
}

func parsePtyOpenPayload(raw []byte) (string, uint16, uint16, error) {
	if len(raw) < 2 {
		return "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	termLen := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+termLen+4 {
		return "", 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	term := string(raw[2 : 2+termLen])
	cols := binary.BigEndian.Uint16(raw[2+termLen : 2+termLen+2])
	rows := binary.BigEndian.Uint16(raw[2+termLen+2 : 2+termLen+4])
	return term, cols, rows, nil
}

func parsePtyResizePayload(raw []byte) (uint16, uint16, error) {
	if len(raw) < 4 {
		return 0, 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return binary.BigEndian.Uint16(raw[:2]), binary.BigEndian.Uint16(raw[2:4]), nil
}

func parsePtySignalPayload(raw []byte) (uint8, error) {
	if len(raw) < 1 {
		return 0, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return raw[0], nil
}

// 构建APP_REP响应，包含事件类型、pty会话ID、退出码和输出数据等信息，并使用当前会话的KeyCV进行加密和签名
func (s *Service) buildAPPRep(current *SessionContext, seq uint32, event uint8, ptySessionID uint32, exitCode int32, payload []byte) []byte {
	signFn := func(cipherData []byte) ([256]byte, error) {
		raw := make([]byte, 4+len(cipherData))
		// 签名内容由序列号和密文数据组成，确保每条消息的签名都是唯一的，并且与消息内容紧密绑定
		copy(raw[:4], krb.Uint32ToBytes(seq))
		copy(raw[4:], cipherData)
		return krb.SignSHA256(raw, s.privKey)
	}
	wire, err := krb.BuildAPPRepPayload(event, ptySessionID, exitCode, payload, current.KeyCV, signFn)
	if err != nil {
		log.Errorf("[V] build APP_REP failed client=%s seq=%d event=%d err=%v", current.IDClient, seq, event, err)
		return wire
	}
	return wire
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	err := krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[V] error response send failed seq=%d code=%d err=%v", seq, code, err)
		return err
	}
	log.Warnf("[V] error response sent seq=%d code=%d", seq, code)
	return nil
}
