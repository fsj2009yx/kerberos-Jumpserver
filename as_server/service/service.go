package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fatedier/golib/log"

	"security-project/as_server/config"
	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
)

type Service struct {
	Config     *config.Config
	state      *krb.ASState
	replay     *krb.ReplayWindow
	startTime  time.Time
	nextSeq    uint32
	httpServer *http.Server
}

func NewService(configPath string) *Service {
	log.Infof("[AS] initializing service config=%s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Errorf("[AS] load config failed config=%s err=%v", configPath, err)
		panic(fmt.Sprintf("load config: %v", err))
	}

	//加载 TGS 密钥 k_tgs，用于加密发给 TGS 的票据和 AS-REP 中的认证数据
	ktgs, err := krb.LoadConfiguredKey8(cfg.KtgsPath, cfg.KtgsHex, "as k_tgs")
	if err != nil {
		log.Errorf("[AS] load k_tgs failed err=%v", err)
		panic(fmt.Sprintf("load k_tgs: %v", err))
	}
	log.Infof("[AS] k_tgs loaded source_configured=%t", cfg.KtgsPath != "" || cfg.KtgsHex != "")
	// 初始化 AS 服务器的状态，包括客户端信息、TGS 密钥和 TGS ID。
	//客户端信息从配置文件中加载，并存储在一个映射中，键是客户端 ID，值是包含客户端 ID、与 TGS 共享的密钥和客户端地址的结构体。
	st := &krb.ASState{
		Clients: make(map[string]krb.ASClientSecret, len(cfg.ClientDB)),
		Ktgs:    ktgs,
		IDTGS:   "TGS",
	}
	for _, c := range cfg.ClientDB {
		kc, err := krb.LoadConfiguredKey8(c.KcPath, c.KcHex, "client "+c.ID+" kc")
		if err != nil {
			log.Errorf("[AS] load client key failed client=%s err=%v", c.ID, err)
			panic(fmt.Sprintf("load client key %s: %v", c.ID, err))
		}
		st.Clients[c.ID] = krb.ASClientSecret{
			IDClient: c.ID,
			Kc:       kc,
			ADc:      c.ADc,
		}
		log.Debugf("[AS] client secret loaded client=%s adc=%d", c.ID, c.ADc)
	}
	log.Infof("[AS] service initialized node_id=%s clients=%d ticket_lifetime=%d anti_replay_window=%d", cfg.NodeID, len(st.Clients), cfg.TicketLifetimeSec, cfg.AntiReplayWindow)
	return &Service{
		Config:    cfg,
		state:     st,
		replay:    krb.NewReplayWindow(cfg.AntiReplayWindow),
		startTime: time.Now(),
	}
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		log.Infof("[AS] starting webui host=%s port=%d", s.Config.WebUIHost, s.Config.WebUIPort)
		go s.runWebUI()
	} else {
		log.Infof("[AS] webui disabled")
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	log.Infof("[AS] opening tcp listener addr=%s", addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("[AS] listen failed addr=%s err=%v", addr, err)
		return err
	}
	defer ln.Close()
	log.Infof("[AS] listening addr=%s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorf("[AS] accept failed addr=%s err=%v", addr, err)
			continue
		}
		log.Infof("[AS] accepted connection remote=%s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *Service) nextServerSeq() uint32 {
	return atomic.AddUint32(&s.nextSeq, 1)
}

func (s *Service) replayScopeForAS(payload []byte) (string, error) {
	req, err := krb.ParseASReqPayload(payload)
	if err != nil {
		return "", err
	}
	return "client:" + string(req.IDClient.Data), nil
}

func (s *Service) handleConnection(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	peerADc := krb.PeerIP(conn)
	log.Infof("[AS] connection started remote=%s peer_adc=%d", remote, peerADc)
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("[AS] connection close returned error remote=%s err=%v", remote, err)
		}
		log.Infof("[AS] connection closed remote=%s", remote)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	for {
		// 每次循环开始时按配置设置读取截止时间，避免连接长时间无响应导致资源泄漏。
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadTimeoutSec) * time.Second))
		// 按配置的最大载荷限制读取一个 Kerberos 协议包。
		h, payload, err := krb.ReadPacket(conn, s.Config.MaxPayloadBytes)
		if err != nil {
			code := krb.CodeFromError(err)
			if code != krb.ErrSocketRecv {
				log.Warnf("[AS] read packet failed remote=%s code=%d err=%v", remote, code, err)
				if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
					log.Warnf("[AS] write read-error response failed remote=%s code=%d err=%v", remote, code, writeErr)
				}
			} else {
				log.Debugf("[AS] read packet ended remote=%s code=%d err=%v", remote, code, err)
			}
			return
		}
		log.Debugf("[AS] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d", remote, h.MsgType, h.SeqNum, len(payload))
		//检查协议头中的消息类型是否为 AS 请求，如果不是，则返回一个错误响应并关闭连接。
		if err := krb.CheckHeaderType(h.MsgType, krb.MsgASReq); err != nil {

			//CodeFromError 函数将错误转换为一个整数错误代码，便于在日志中记录和在响应中使用。
			code := krb.CodeFromError(err)
			log.Warnf("[AS] invalid message type remote=%s msg_type=%d code=%d err=%v", remote, h.MsgType, code, err)
			if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
				log.Warnf("[AS] write invalid-type response failed remote=%s code=%d err=%v", remote, code, writeErr)
			}
			return
		}

		scope, err := s.replayScopeForAS(payload)
		if err != nil {
			code := krb.CodeFromError(err)
			log.Warnf("[AS] replay scope parse failed remote=%s code=%d err=%v", remote, code, err)
			if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
				log.Warnf("[AS] write replay-scope response failed remote=%s code=%d err=%v", remote, code, writeErr)
			}
			return
		}
		if err := s.replay.CheckScoped(scope, h.Timestamp, h.SeqNum); err != nil {
			code := krb.CodeFromError(err)
			log.Warnf("[AS] replay check failed remote=%s scope=%s seq=%d ts=%d code=%d err=%v", remote, scope, h.SeqNum, h.Timestamp, code, err)
			if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
				log.Warnf("[AS] write replay response failed remote=%s code=%d err=%v", remote, code, writeErr)
			}
			return
		}
		log.Debugf("[AS] replay check passed remote=%s scope=%s seq=%d ts=%d", remote, scope, h.SeqNum, h.Timestamp)

		//peerADc 是从连接中提取的客户端 IP 地址，用于后续的处理。
		//handleASReq 函数根据协议头、负载数据和客户端 IP 地址处理 AS 请求，并返回响应类型、响应负载和可能发生的错误。
		respType, respPayload, respErr := s.handleASReq(h, payload, peerADc)
		if respErr != nil {
			code := krb.CodeFromError(respErr)
			log.Warnf("[AS] AS_REQ handling failed remote=%s seq=%d code=%d err=%v", remote, h.SeqNum, code, respErr)
			if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
				log.Warnf("[AS] write AS_REQ error response failed remote=%s code=%d err=%v", remote, code, writeErr)
			}
			return
		}
		if err := krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload); err != nil {
			log.Errorf("[AS] write response failed remote=%s msg_type=%d err=%v", remote, respType, err)
			return
		}
		log.Infof("[AS] AS response sent remote=%s req_seq=%d msg_type=%d payload_bytes=%d", remote, h.SeqNum, respType, len(respPayload))
		return
	}
}

func (s *Service) handleASReq(h krb.ProtocolHeader, payload []byte, peerADc uint32) (uint8, []byte, error) {
	req, err := krb.ParseASReqPayload(payload)
	if err != nil {
		log.Warnf("[AS] parse AS_REQ failed seq=%d payload_bytes=%d err=%v", h.SeqNum, len(payload), err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	clientID := string(req.IDClient.Data)
	idTGS := string(req.IDTGS.Data)
	if idTGS == "" {
		idTGS = s.state.IDTGS
	}
	log.Infof("[AS] AS_REQ received client=%s id_tgs=%s seq=%d ts=%d peer_adc=%d", clientID, idTGS, h.SeqNum, h.Timestamp, peerADc)
	secret, ok := s.state.Clients[clientID]
	if !ok {
		err := krb.ErrorFromCode(krb.ErrClientNotFound)
		log.Warnf("[AS] AS_REQ rejected unknown client=%s seq=%d code=%d", clientID, h.SeqNum, krb.ErrClientNotFound)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrClientNotFound), err
	}
	secret.ADc = peerADc
	//keyCTGS是C和TGS之间的会话密钥，AS生成后发送给C，C再转发给TGS
	//TGS用它来验证AS发来的票据和加密的认证数据，并在TGS-REP中使用它加密返回给C的认证数据。
	keyCTGS, err := rand8()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrKeyDerive)
		log.Errorf("[AS] generate K_c_tgs failed client=%s seq=%d err=%v", clientID, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrKeyDerive), err
	}
	ts2 := uint32(time.Now().Unix())

	// 生成发给TGS的票据，包含C的身份、TGS的身份、keyCTGS、ts2和票据有效期
	ticketPlain, err := krb.BuildTicketTGSPlain(secret, idTGS, keyCTGS, ts2, s.Config.TicketLifetimeSec)
	if err != nil {
		log.Warnf("[AS] build TGT plain failed client=%s id_tgs=%s seq=%d err=%v", clientID, idTGS, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}

	ticketCipher, err := cryptoutil.EncryptDESCBC(s.state.Ktgs, ticketPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[AS] encrypt TGT failed client=%s id_tgs=%s seq=%d err=%v", clientID, idTGS, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	innerPlain, err := krb.BuildASRepPlain(keyCTGS, idTGS, ts2, s.Config.TicketLifetimeSec, ticketCipher)
	if err != nil {
		log.Warnf("[AS] build AS_REP plain failed client=%s id_tgs=%s seq=%d err=%v", clientID, idTGS, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	encPart, err := cryptoutil.EncryptDESCBC(secret.Kc, innerPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[AS] encrypt AS_REP failed client=%s id_tgs=%s seq=%d err=%v", clientID, idTGS, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	resp, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		log.Warnf("[AS] build AS_REP payload failed client=%s id_tgs=%s seq=%d err=%v", clientID, idTGS, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	log.Infof("[AS] TGT issued client=%s id_tgs=%s seq=%d ts2=%d lifetime=%d payload_bytes=%d", clientID, idTGS, h.SeqNum, ts2, s.Config.TicketLifetimeSec, len(resp))
	return krb.MsgASRep, resp, nil
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	remote := "<nil>"
	if conn != nil {
		remote = conn.RemoteAddr().String()
	}
	err := krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[AS] error response send failed remote=%s seq=%d code=%d err=%v", remote, seq, code, err)
		return err
	}
	log.Warnf("[AS] error response sent remote=%s seq=%d code=%d", remote, seq, code)
	return nil
}

// rand8 生成一个随机的 8 字节数组，返回生成的字节数组和一个状态码。
// 如果生成过程中发生错误，返回一个全零的字节数组和一个错误状态码。
func rand8() ([8]byte, error) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
