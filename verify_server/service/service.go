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
	replay      *krb.ReplayWindow
	startTime   time.Time
	nextSeq     uint32
	nextPtyID   uint32
	privKey     *crypto.RSAKey
	clientCerts map[string]*krb.Certificate
	httpServer  *http.Server
}

func NewService(configPath string) *Service {
	log.Infof("[V] initializing service config=%s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Errorf("[V] load config failed config=%s err=%v", configPath, err)
		panic(fmt.Sprintf("load config: %v", err))
	}
	kv, err := krb.LoadConfiguredKey8(cfg.KVPath, cfg.KVHex, "v k_v")
	if err != nil {
		log.Errorf("[V] load k_v failed err=%v", err)
		panic(fmt.Sprintf("load k_v: %v", err))
	}
	log.Infof("[V] k_v loaded source_configured=%t", cfg.KVPath != "" || cfg.KVHex != "")
	priv, err := krb.LoadRSAPrivateKey(cfg.PrivKeyPath)
	if err != nil {
		log.Errorf("[V] load private key failed path=%s err=%v", cfg.PrivKeyPath, err)
		panic(fmt.Sprintf("load private key: %v", err))
	}
	log.Infof("[V] private key loaded path=%s", cfg.PrivKeyPath)
	s := &Service{
		Config:      cfg,
		state:       &VState{SeqNum: 1, IDV: cfg.NodeID, Kv: kv, Sessions: make(map[string]*SessionContext)},
		replay:      krb.NewReplayWindow(cfg.AntiReplayWindow),
		startTime:   time.Now(),
		privKey:     priv,
		clientCerts: make(map[string]*krb.Certificate),
	}
	for _, item := range cfg.ClientDB {
		if item.CertPath == "" {
			log.Debugf("[V] client cert skipped client=%s reason=empty_path", item.ID)
			continue
		}
		cert, err := krb.CertLoad(item.CertPath)
		if err != nil {
			log.Warnf("[V] client cert load failed client=%s path=%s err=%v", item.ID, item.CertPath, err)
			continue
		}
		s.clientCerts[item.ID] = cert
		log.Debugf("[V] client cert loaded client=%s path=%s", item.ID, item.CertPath)
	}
	log.Infof("[V] service initialized node_id=%s clients=%d certs=%d pty_shell=%s anti_replay_window=%d", cfg.NodeID, len(cfg.ClientDB), len(s.clientCerts), cfg.PTYShell, cfg.AntiReplayWindow)
	return s
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		log.Infof("[V] starting webui host=%s port=%d", s.Config.WebUIHost, s.Config.WebUIPort)
		go s.runWebUI()
	} else {
		log.Infof("[V] webui disabled")
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	log.Infof("[V] opening tcp listener addr=%s", addr)
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
			log.Errorf("[V] accept failed addr=%s err=%v", addr, err)
			continue
		}
		log.Infof("[V] accepted connection remote=%s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *Service) nextServerSeq() uint32 {
	return atomic.AddUint32(&s.nextSeq, 1)
}

func (s *Service) nextSessionID() uint32 {
	return atomic.AddUint32(&s.nextPtyID, 1)
}

func nextAppSeq(current *SessionContext) uint32 {
	if current == nil {
		return 0
	}
	return atomic.AddUint32(&current.SendSeq, 1)
}

func (s *Service) replayScopeForAPReq(payload []byte) (string, error) {
	req, err := krb.ParseAPReqPayload(payload)
	if err != nil {
		return "", err
	}
	ticket, err := krb.DecodeTicketV(req.TicketV, s.state.Kv)
	if err != nil {
		return "", err
	}
	return "client:" + string(ticket.IDClient.Data), nil
}

func (s *Service) handleConnection(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	peerADc := krb.PeerIP(conn)
	log.Infof("[V] connection started remote=%s peer_adc=%d", remote, peerADc)
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("[V] connection close returned error remote=%s err=%v", remote, err)
		}
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
			log.Errorf("[V] packet send failed remote=%s msg_type=%d seq=%d payload_bytes=%d err=%v", remote, msgType, seq, len(payload), err)
			return err
		}
		log.Debugf("[V] packet sent remote=%s msg_type=%d seq=%d payload_bytes=%d", remote, msgType, seq, len(payload))
		return nil
	}
	sendPacket := func(msgType uint8, payload []byte) error {
		return sendPacketWithSeq(msgType, s.nextServerSeq(), payload)
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
				if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
					log.Warnf("[V] write read-error response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
			} else {
				log.Debugf("[V] read packet ended remote=%s code=%d err=%v", remote, code, err)
			}
			return
		}
		log.Debugf("[V] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d authed=%t", remote, h.MsgType, h.SeqNum, len(payload), authed)
		switch h.MsgType {
		case krb.MsgAPReq:
			if authed {
				log.Warnf("[V] duplicate AP_REQ rejected remote=%s seq=%d code=%d", remote, h.SeqNum, krb.ErrMsgTypeInvalid)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid)); writeErr != nil {
					log.Warnf("[V] duplicate AP_REQ error response failed remote=%s err=%v", remote, writeErr)
				}
				return
			}
			scope, err := s.replayScopeForAPReq(payload)
			if err != nil {
				code := krb.CodeFromError(err)
				log.Warnf("[V] AP replay scope parse failed remote=%s code=%d err=%v", remote, code, err)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(code)); writeErr != nil {
					log.Warnf("[V] AP replay-scope response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
				return
			}
			if err := s.replay.CheckScoped(scope, h.Timestamp, h.SeqNum); err != nil {
				code := krb.CodeFromError(err)
				log.Warnf("[V] AP replay check failed remote=%s scope=%s seq=%d ts=%d code=%d err=%v", remote, scope, h.SeqNum, h.Timestamp, code, err)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(code)); writeErr != nil {
					log.Warnf("[V] AP replay response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
				return
			}
			log.Debugf("[V] AP replay check passed remote=%s scope=%s seq=%d ts=%d", remote, scope, h.SeqNum, h.Timestamp)
			respPayload, sess, err := s.handleAPReq(ctx, h, payload, sendPacket)
			if err != nil {
				code := krb.CodeFromError(err)
				log.Warnf("[V] AP_REQ handling failed remote=%s seq=%d code=%d err=%v", remote, h.SeqNum, code, err)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(code)); writeErr != nil {
					log.Warnf("[V] AP_REQ error response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
				return
			}
			authed = true
			current = sess
			if err := sendPacket(krb.MsgAPRep, respPayload); err != nil {
				return
			}
			log.Infof("[V] AP authentication accepted remote=%s client=%s seq=%d session_expire=%d", remote, current.IDClient, h.SeqNum, current.ExpireAt)
		case krb.MsgApp:
			if !authed || current == nil {
				log.Warnf("[V] app frame rejected without session remote=%s seq=%d code=%d", remote, h.SeqNum, krb.ErrSessionNotFound)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrSessionNotFound)); writeErr != nil {
					log.Warnf("[V] no-session error response failed remote=%s err=%v", remote, writeErr)
				}
				return
			}
			if err := s.replay.CheckScoped("client:"+current.IDClient, h.Timestamp, h.SeqNum); err != nil {
				code := krb.CodeFromError(err)
				log.Warnf("[V] app replay check failed remote=%s client=%s seq=%d ts=%d code=%d err=%v", remote, current.IDClient, h.SeqNum, h.Timestamp, code, err)
				if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(code)); writeErr != nil {
					log.Warnf("[V] app replay response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
				return
			}
			respSeq := nextAppSeq(current)
			respType, respPayload, respErr := s.handleAPPReq(h, payload, current, sendPacketWithSeq, respSeq)
			if respErr != nil {
				log.Warnf("[V] APP_REQ handling failed remote=%s client=%s req_seq=%d resp_seq=%d err=%v", remote, current.IDClient, h.SeqNum, respSeq, respErr)
				if writeErr := sendPacketWithSeq(respType, respSeq, respPayload); writeErr != nil {
					log.Warnf("[V] APP_REQ error response failed remote=%s client=%s resp_seq=%d err=%v", remote, current.IDClient, respSeq, writeErr)
				}
				return
			}
			if err := sendPacketWithSeq(respType, respSeq, respPayload); err != nil {
				return
			}
			log.Infof("[V] APP response sent remote=%s client=%s req_seq=%d resp_seq=%d msg_type=%d payload_bytes=%d", remote, current.IDClient, h.SeqNum, respSeq, respType, len(respPayload))
			if current != nil && current.Closed {
				log.Infof("[V] session closed remote=%s client=%s pty_session_id=%d", remote, current.IDClient, current.PtySessionID)
				return
			}
			if respType == krb.MsgApp {
				continue
			}
			return
		default:
			log.Warnf("[V] invalid message type remote=%s msg_type=%d seq=%d code=%d", remote, h.MsgType, h.SeqNum, krb.ErrMsgTypeInvalid)
			if writeErr := sendPacket(krb.MsgErr, krb.BuildErrorPayload(krb.ErrMsgTypeInvalid)); writeErr != nil {
				log.Warnf("[V] invalid-type response failed remote=%s err=%v", remote, writeErr)
			}
			return
		}
	}
}

func (s *Service) handleAPReq(connCtx context.Context, h krb.ProtocolHeader, payload []byte, sendPacket func(uint8, []byte) error) ([]byte, *SessionContext, error) {
	req, err := krb.ParseAPReqPayload(payload)
	if err != nil {
		log.Warnf("[V] parse AP_REQ failed seq=%d payload_bytes=%d err=%v", h.SeqNum, len(payload), err)
		return nil, nil, err
	}
	log.Infof("[V] AP_REQ received seq=%d ts=%d payload_bytes=%d", h.SeqNum, h.Timestamp, len(payload))
	ticket, err := krb.DecodeTicketV(req.TicketV, s.state.Kv)
	if err != nil {
		log.Warnf("[V] decode service ticket failed seq=%d err=%v", h.SeqNum, err)
		return nil, nil, err
	}
	clientID := string(ticket.IDClient.Data)
	if ticket.IDV.Len > 0 && string(ticket.IDV.Data) != s.state.IDV {
		log.Warnf("[V] service ticket rejected wrong id_v=%s expected=%s client=%s seq=%d code=%d", string(ticket.IDV.Data), s.state.IDV, clientID, h.SeqNum, krb.ErrTicketInvalid)
		return nil, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	if uint32(time.Now().Unix()) > ticket.TS4+ticket.Lifetime {
		log.Warnf("[V] service ticket expired client=%s seq=%d expire=%d code=%d", clientID, h.SeqNum, ticket.TS4+ticket.Lifetime, krb.ErrTicketExpired)
		return nil, nil, krb.ErrorFromCode(krb.ErrTicketExpired)
	}
	auth, err := krb.DecodeAuthenticatorCV(req.AuthCipher, ticket.KeyCV)
	if err != nil {
		log.Warnf("[V] decode AP authenticator failed client=%s seq=%d err=%v", clientID, h.SeqNum, err)
		return nil, nil, err
	}
	if string(auth.IDClient.Data) != clientID {
		log.Warnf("[V] AP authenticator client mismatch auth_client=%s ticket_client=%s seq=%d code=%d", string(auth.IDClient.Data), clientID, h.SeqNum, krb.ErrAuthMismatch)
		return nil, nil, krb.ErrorFromCode(krb.ErrAuthMismatch)
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc {
		log.Warnf("[V] AP authenticator address mismatch client=%s auth_adc=%d ticket_adc=%d seq=%d code=%d", clientID, auth.ADc, ticket.ADc, h.SeqNum, krb.ErrADMismatch)
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
	log.Infof("[V] session created client=%s seq=%d expire_at=%d adc=%d", sess.IDClient, h.SeqNum, sess.ExpireAt, sess.ADc)

	resp, err := krb.BuildAPRepPayload(auth.TS5, ticket.KeyCV)
	if err != nil {
		log.Warnf("[V] build AP_REP failed client=%s seq=%d err=%v", sess.IDClient, h.SeqNum, err)
		return nil, nil, err
	}
	log.Infof("[V] AP_REP built client=%s seq=%d payload_bytes=%d", sess.IDClient, h.SeqNum, len(resp))
	return resp, sess, nil
}

func (s *Service) handleAPPReq(h krb.ProtocolHeader, payload []byte, current *SessionContext, sendPacket func(uint8, uint32, []byte) error, respSeq uint32) (uint8, []byte, error) {
	req, err := krb.ParseAPPReqPayload(payload)
	if err != nil {
		log.Warnf("[V] parse APP_REQ failed client=%s seq=%d payload_bytes=%d err=%v", current.IDClient, h.SeqNum, len(payload), err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if req.IDClient.Len > 0 && string(req.IDClient.Data) != current.IDClient {
		err := krb.ErrorFromCode(krb.ErrCertIDMismatch)
		log.Warnf("[V] APP_REQ client mismatch session_client=%s req_client=%s seq=%d code=%d", current.IDClient, string(req.IDClient.Data), h.SeqNum, krb.ErrCertIDMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertIDMismatch), err
	}
	if uint32(time.Now().Unix()) > current.ExpireAt {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		log.Warnf("[V] APP_REQ rejected expired session client=%s seq=%d expire_at=%d code=%d", current.IDClient, h.SeqNum, current.ExpireAt, krb.ErrTicketExpired)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	if cert := s.clientCerts[current.IDClient]; cert != nil {
		pub, err := cert.PublicKeyRSA()
		if err != nil {
			err := krb.ErrorFromCode(krb.ErrCertSigInvalid)
			log.Warnf("[V] client cert public key parse failed client=%s seq=%d code=%d", current.IDClient, h.SeqNum, krb.ErrCertSigInvalid)
			return krb.MsgErr, krb.BuildErrorPayload(krb.ErrCertSigInvalid), err
		}
		if err := krb.VerifyCipherSignature(h.SeqNum, req.Cipher, req.RSASignC, pub); err != nil {
			log.Warnf("[V] APP_REQ signature verify failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
			return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
		}
		log.Debugf("[V] APP_REQ signature verified client=%s seq=%d", current.IDClient, h.SeqNum)
	}

	plain, err := krb.DecryptAPPReqPlain(req.Cipher, current.KeyCV)
	if err != nil {
		log.Warnf("[V] APP_REQ decrypt failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("decrypt failed")), err
	}
	atomic.AddUint64(&current.TotalFrames, 1)
	current.LastIO = time.Now()
	log.Infof("[V] APP_REQ received client=%s seq=%d resp_seq=%d pty_op=%d pty_session_id=%d payload_bytes=%d", current.IDClient, h.SeqNum, respSeq, plain.PtyOp, plain.PtySessionID, len(plain.Payload))

	switch plain.PtyOp {
	case ptyOpOpen:
		term, cols, rows, err := parsePtyOpenPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] parse pty open payload failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad open payload")), err
		}
		if term == "" {
			term = s.Config.PTYDefaultTerm
		}
		if current.PTY != nil {
			if err := current.PTY.Close(); err != nil {
				log.Debugf("[V] previous pty close returned error client=%s pty_session_id=%d err=%v", current.IDClient, current.PtySessionID, err)
			}
			log.Infof("[V] previous pty closed client=%s pty_session_id=%d", current.IDClient, current.PtySessionID)
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
		go s.streamPTYOutput(current, sendPacket)
		out := []byte(fmt.Sprintf("open ok: %s", current.IDClient))
		log.Infof("[V] pty opened client=%s pty_session_id=%d shell=%s term=%s cols=%d rows=%d", current.IDClient, current.PtySessionID, s.Config.PTYShell, term, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOpenOK, current.PtySessionID, -1, out), nil
	case ptyOpInput:
		if current.PTY == nil {
			log.Warnf("[V] pty input rejected because pty not open client=%s seq=%d code=%d", current.IDClient, h.SeqNum, krb.ErrSessionNotFound)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		if _, err := current.PTY.PTY.Write(plain.Payload); err != nil {
			log.Warnf("[V] pty input write failed client=%s pty_session_id=%d payload_bytes=%d err=%v", current.IDClient, current.PtySessionID, len(plain.Payload), err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty write failed")), krb.ErrorFromCode(krb.ErrSocketSend)
		}
		out := append([]byte("echo: "), plain.Payload...)
		log.Infof("[V] pty input accepted client=%s pty_session_id=%d payload_bytes=%d", current.IDClient, current.PtySessionID, len(plain.Payload))
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, out), nil
	case ptyOpResize:
		if current.PTY == nil {
			log.Warnf("[V] pty resize rejected because pty not open client=%s seq=%d code=%d", current.IDClient, h.SeqNum, krb.ErrSessionNotFound)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		cols, rows, err := parsePtyResizePayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] parse pty resize payload failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad resize payload")), err
		}
		if err := current.PTY.Resize(cols, rows); err != nil {
			log.Warnf("[V] pty resize failed client=%s pty_session_id=%d cols=%d rows=%d err=%v", current.IDClient, current.PtySessionID, cols, rows, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("resize failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Infof("[V] pty resized client=%s pty_session_id=%d cols=%d rows=%d", current.IDClient, current.PtySessionID, cols, rows)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventOutput, current.PtySessionID, -1, []byte("resize ok")), nil
	case ptyOpSignal:
		if current.PTY == nil {
			log.Warnf("[V] pty signal rejected because pty not open client=%s seq=%d code=%d", current.IDClient, h.SeqNum, krb.ErrSessionNotFound)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		sig, err := parsePtySignalPayload(plain.Payload)
		if err != nil {
			log.Warnf("[V] parse pty signal payload failed client=%s seq=%d err=%v", current.IDClient, h.SeqNum, err)
			return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("bad signal payload")), err
		}
		if err := current.PTY.Signal(sig); err != nil {
			log.Warnf("[V] pty signal failed client=%s pty_session_id=%d signal=%d err=%v", current.IDClient, current.PtySessionID, sig, err)
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
				log.Debugf("[V] pty close returned error client=%s pty_session_id=%d err=%v", current.IDClient, current.PtySessionID, err)
			}
		}
		s.state.mu.Lock()
		delete(s.state.Sessions, current.IDClient)
		s.state.mu.Unlock()
		current.Closed = true
		log.Infof("[V] pty session closed client=%s pty_session_id=%d total_frames=%d", current.IDClient, current.PtySessionID, atomic.LoadUint64(&current.TotalFrames))
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventExit, current.PtySessionID, 0, []byte("bye")), nil
	default:
		log.Warnf("[V] invalid pty operation client=%s seq=%d pty_op=%d code=%d", current.IDClient, h.SeqNum, plain.PtyOp, krb.ErrMsgTypeInvalid)
		return krb.MsgApp, s.buildAPPRep(current, respSeq, ptyEventError, current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrorFromCode(krb.ErrMsgTypeInvalid)
	}
}

func (s *Service) streamPTYOutput(current *SessionContext, sendPacket func(uint8, uint32, []byte) error) {
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
		current.LastIO = time.Now()
		seq := nextAppSeq(current)
		rep := s.buildAPPRep(current, seq, ptyEventOutput, current.PtySessionID, -1, data)
		if err := sendPacket(krb.MsgApp, seq, rep); err != nil {
			log.Warnf("[V] pty output send failed client=%s pty_session_id=%d seq=%d payload_bytes=%d err=%v", current.IDClient, current.PtySessionID, seq, len(data), err)
			return
		}
		log.Debugf("[V] pty output sent client=%s pty_session_id=%d seq=%d payload_bytes=%d", current.IDClient, current.PtySessionID, seq, len(data))
	}
	if current.Closed {
		log.Infof("[V] pty output stream ended after session close client=%s pty_session_id=%d", current.IDClient, current.PtySessionID)
		return
	}
	seq := nextAppSeq(current)
	rep := s.buildAPPRep(current, seq, ptyEventExit, current.PtySessionID, 0, nil)
	if err := sendPacket(krb.MsgApp, seq, rep); err != nil {
		log.Warnf("[V] pty exit event send failed client=%s pty_session_id=%d seq=%d err=%v", current.IDClient, current.PtySessionID, seq, err)
		return
	}
	log.Infof("[V] pty output stream ended client=%s pty_session_id=%d exit_seq=%d", current.IDClient, current.PtySessionID, seq)
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
		log.Errorf("[V] build APP_REP failed client=%s seq=%d event=%d pty_session_id=%d err=%v", current.IDClient, seq, event, ptySessionID, err)
		return wire
	}
	log.Debugf("[V] APP_REP built client=%s seq=%d event=%d pty_session_id=%d payload_bytes=%d", current.IDClient, seq, event, ptySessionID, len(payload))
	return wire
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	remote := "<nil>"
	if conn != nil {
		remote = conn.RemoteAddr().String()
	}
	err := krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[V] error response send failed remote=%s seq=%d code=%d err=%v", remote, seq, code, err)
		return err
	}
	log.Warnf("[V] error response sent remote=%s seq=%d code=%d", remote, seq, code)
	return nil
}
