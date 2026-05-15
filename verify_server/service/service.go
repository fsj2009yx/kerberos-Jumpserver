package service

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"security-project/common/crypto"
	"security-project/common/krb"
	"security-project/pkg/utils/log"
	"security-project/verify_server/config"
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

	// 加载服务端配置的密钥材料，包括KV和RSA私钥，以及客户端证书等信息，并初始化服务状态
	kv, err := krb.LoadConfiguredKey8(cfg.KVPath, cfg.KVHex, "v k_v")
	if err != nil {
		log.Errorf("[V] load k_v failed err=%v", err)
		panic(fmt.Sprintf("load k_v: %v", err))
	}

	// 加载RSA私钥用于后续的消息签名操作，确保服务端能够对发送的消息进行数字签名，以便客户端验证消息的真实性和完整性
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
		// 加载客户端证书并存储在服务端的内存中，以便在处理客户端请求时能够验证客户端的身份和消息的签名
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

func (s *Service) handleConnection(conn net.Conn) {
	c := NewConnState(conn, s.Config.AntiReplayWindow)
	defer c.close()
	c.closeOnCancel()

	for {
		h, payload, err := c.readPacket(s.Config.ReadTimeoutSec, s.Config.MaxPayloadBytes)
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
			if s.handleAPReqPacket(c, h, payload) {
				continue
			}
			return
		case krb.MsgApp:
			if s.handleAppPacket(c, h, payload) {
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

func (s *Service) handleAPReqPacket(c *ConnState, h krb.ProtocolHeader, payload []byte) bool {
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
	respPayload, sess, err := s.handleAPReq(c.ctx, h, payload, c.sendPacket)
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

func (s *Service) handleAppPacket(c *ConnState, h krb.ProtocolHeader, payload []byte) bool {
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
	respType, respPayload, respErr := s.handleAPPReq(h, payload, c.current, c.sendPacketWithSeq, respSeq, c.nextSeq)
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

func (s *Service) nextSessionID() uint32 {
	return atomic.AddUint32(&s.nextPtyID, 1)
}
