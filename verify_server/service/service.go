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
	audit       *AuditStore
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
	if cfg.CertPath != "" {
		cert, err := krb.CertLoad(cfg.CertPath)
		if err != nil {
			log.Errorf("[V] load own certificate failed path=%s err=%v", cfg.CertPath, err)
			panic(fmt.Sprintf("load own certificate: %v", err))
		}
		if err := krb.CertVerify(cert); err != nil {
			log.Errorf("[V] verify own certificate failed path=%s err=%v", cfg.CertPath, err)
			panic(fmt.Sprintf("verify own certificate: %v", err))
		}
		if cert.ID != cfg.NodeID {
			log.Errorf("[V] own certificate id mismatch cert_id=%s node_id=%s", cert.ID, cfg.NodeID)
			panic("own certificate id mismatch")
		}
	}
	auditPath := cfg.AuditPath()
	audit, err := NewAuditStore(auditPath)
	if err != nil {
		log.Errorf("[V] init audit store failed path=%s err=%v", auditPath, err)
		panic(fmt.Sprintf("init audit store: %v", err))
	}
	s := &Service{
		Config:      cfg,
		state:       &VState{IDV: cfg.NodeID, Kv: kv, Sessions: make(map[string]*SessionContext)},
		startTime:   time.Now(),
		privKey:     priv,
		clientCerts: make(map[string]*krb.Certificate),
		audit:       audit,
	}
	for _, item := range cfg.ClientDB {
		if item.CertPath == "" {
			log.Errorf("[V] client cert missing client=%s", item.ID)
			panic(fmt.Sprintf("client cert missing: %s", item.ID))
		}
		// 加载客户端证书并存储在服务端的内存中，以便在处理客户端请求时能够验证客户端的身份和消息的签名
		cert, err := krb.CertLoad(item.CertPath)
		if err != nil {
			log.Errorf("[V] client cert load failed client=%s path=%s err=%v", item.ID, item.CertPath, err)
			panic(fmt.Sprintf("load client cert %s: %v", item.ID, err))
		}
		if err := krb.CertVerify(cert); err != nil {
			log.Errorf("[V] client cert verify failed client=%s path=%s err=%v", item.ID, item.CertPath, err)
			panic(fmt.Sprintf("verify client cert %s: %v", item.ID, err))
		}
		if cert.ID != item.ID {
			log.Errorf("[V] client cert id mismatch config_id=%s cert_id=%s", item.ID, cert.ID)
			panic(fmt.Sprintf("client cert id mismatch: %s", item.ID))
		}
		s.clientCerts[item.ID] = cert
		log.Infof("[V] client cert loaded and verified client=%s path=%s", item.ID, item.CertPath)
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

	// 为每个新连接创建一个连接状态对象，并在处理过程中维护该对象的状态
	c := NewConnState(conn, s.Config.AntiReplayWindow)
	defer c.close()
	c.closeOnCancel()

	for {
		h, payload, err := c.readPacket(s.Config.MaxPayloadBytes)
		if err != nil {
			code := krb.CodeFromError(err)
			if code != krb.ErrSocketRecv {
				log.Warnf("[V] read packet failed remote=%s code=%s err=%v", c.remote, krb.FormatCode(code), err)
				_ = c.writeError(c.nextSeq(), code)
			}
			return
		}
		log.Infof("[V] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d authed=%t", c.remote, h.MsgType, h.SeqNum, len(payload), c.authed)
		if err := krb.CheckPacketType(h, payload, krb.MsgAPReq, krb.MsgApp); err != nil {
			code := krb.CodeFromError(err)
			if peerCode, ok := krb.PeerErrorCode(err); ok {
				log.Warnf("[V] peer error response received remote=%s seq=%d code=%s desc=%q", c.remote, h.SeqNum, krb.FormatCode(peerCode), krb.CodeDescription(peerCode))
				return
			}
			log.Warnf("[V] invalid message type remote=%s msg_type=%d seq=%d code=%s err=%v", c.remote, h.MsgType, h.SeqNum, krb.FormatCode(code), err)
			_ = c.writeError(c.nextSeq(), code)
			return
		}
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
			_ = c.writeError(c.nextSeq(), krb.ErrMsgTypeInvalid)
			return
		}
	}
}

func (s *Service) nextSessionID() uint32 {
	return atomic.AddUint32(&s.nextPtyID, 1)
}
