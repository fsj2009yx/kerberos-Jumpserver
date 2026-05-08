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

	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
	"security-project/tgs_server/config"
)

type Service struct {
	Config     *config.Config
	state      *krb.TGSState
	replay     *krb.ReplayWindow
	startTime  time.Time
	nextSeq    uint32
	httpServer *http.Server
}

func NewService(configPath string) *Service {
	log.Infof("[TGS] initializing service config=%s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Errorf("[TGS] load config failed config=%s err=%v", configPath, err)
		panic(fmt.Sprintf("load config: %v", err))
	}
	//加载 TGS 密钥 k_tgs，解密AS发来的Ticket
	ktgs, err := krb.LoadConfiguredKey8(cfg.KTGSPath, cfg.KTGSHex, "tgs k_tgs")
	if err != nil {
		log.Errorf("[TGS] load k_tgs failed err=%v", err)
		panic(fmt.Sprintf("load k_tgs: %v", err))
	}
	log.Infof("[TGS] k_tgs loaded source_configured=%t", cfg.KTGSPath != "" || cfg.KTGSHex != "")
	st := &krb.TGSState{
		Ktgs:     ktgs,
		IDTGS:    "TGS",
		Services: make(map[string]krb.ServiceSecret, len(cfg.ServiceDB)),
	}
	for _, s := range cfg.ServiceDB {
		//加载服务密钥 k_v，用于加密发给客户端的票据和 TGS-REP 中的认证数据
		kv, err := krb.LoadConfiguredKey8(s.KVPath, s.KVHex, "service "+s.IDV+" k_v")
		if err != nil {
			log.Errorf("[TGS] load service key failed service=%s err=%v", s.IDV, err)
			panic(fmt.Sprintf("load service key %s: %v", s.IDV, err))
		}
		st.Services[s.IDV] = krb.ServiceSecret{IDV: s.IDV, Kv: kv}
		log.Debugf("[TGS] service secret loaded service=%s addr=%s", s.IDV, s.Addr)
	}
	log.Infof("[TGS] service initialized node_id=%s services=%d ticket_lifetime=%d anti_replay_window=%d", cfg.NodeID, len(st.Services), cfg.TicketLifetimeSec, cfg.AntiReplayWindow)
	return &Service{
		Config:    cfg,
		state:     st,
		replay:    krb.NewReplayWindow(cfg.AntiReplayWindow),
		startTime: time.Now(),
	}
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		log.Infof("[TGS] starting webui host=%s port=%d", s.Config.WebUIHost, s.Config.WebUIPort)
		go s.runWebUI()
	} else {
		log.Infof("[TGS] webui disabled")
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	log.Infof("[TGS] opening tcp listener addr=%s", addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("[TGS] listen failed addr=%s err=%v", addr, err)
		return err
	}
	defer ln.Close()
	log.Infof("[TGS] listening addr=%s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorf("[TGS] accept failed addr=%s err=%v", addr, err)
			continue
		}
		log.Infof("[TGS] accepted connection remote=%s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

// nextServerSeq 返回一个递增的服务器序列号，用于每个响应包的协议头中的 SeqNum 字段。它使用 atomic 包来保证在并发环境下的安全递增。
func (s *Service) nextServerSeq() uint32 {
	return atomic.AddUint32(&s.nextSeq, 1)
}

// replayScopeForTGS 从 TGS 请求的负载中解析出一个用于重放攻击检测的作用域字符串。
// 它首先解析 TGS 请求的负载，提取其中的票据，然后从票据中获取客户端 ID，并将其作为作用域的一部分返回。
// 这个作用域字符串将用于后续的重放攻击检测，以确保同一客户端的请求不会被重复接受。
func (s *Service) replayScopeForTGS(payload []byte) (string, error) {
	req, err := krb.ParseTGSReqPayload(payload)
	if err != nil {
		return "", err
	}
	ticket, err := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if err != nil {
		return "", err
	}
	return "client:" + string(ticket.IDClient.Data), nil
}

func (s *Service) handleConnection(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	peerADc := krb.PeerIP(conn)
	log.Infof("[TGS] connection started remote=%s peer_adc=%d", remote, peerADc)
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("[TGS] connection close returned error remote=%s err=%v", remote, err)
		}
		log.Infof("[TGS] connection closed remote=%s", remote)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadTimeoutSec) * time.Second))
	h, payload, err := krb.ReadPacket(conn, s.Config.MaxPayloadBytes)
	if err != nil {
		code := krb.CodeFromError(err)
		if code != krb.ErrSocketRecv {
			log.Warnf("[TGS] read packet failed remote=%s code=%d err=%v", remote, code, err)
			if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
				log.Warnf("[TGS] write read-error response failed remote=%s code=%d err=%v", remote, code, writeErr)
			}
		} else {
			log.Debugf("[TGS] read packet ended remote=%s code=%d err=%v", remote, code, err)
		}
		return
	}
	log.Debugf("[TGS] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d", remote, h.MsgType, h.SeqNum, len(payload))
	if err := krb.CheckHeaderType(h.MsgType, krb.MsgTGSReq); err != nil {
		code := krb.CodeFromError(err)
		log.Warnf("[TGS] invalid message type remote=%s msg_type=%d code=%d err=%v", remote, h.MsgType, code, err)
		if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
			log.Warnf("[TGS] write invalid-type response failed remote=%s code=%d err=%v", remote, code, writeErr)
		}
		return
	}
	scope, err := s.replayScopeForTGS(payload)
	if err != nil {
		code := krb.CodeFromError(err)
		log.Warnf("[TGS] replay scope parse failed remote=%s code=%d err=%v", remote, code, err)
		if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
			log.Warnf("[TGS] write replay-scope response failed remote=%s code=%d err=%v", remote, code, writeErr)
		}
		return
	}
	if err := s.replay.CheckScoped(scope, h.Timestamp, h.SeqNum); err != nil {
		code := krb.CodeFromError(err)
		log.Warnf("[TGS] replay check failed remote=%s scope=%s seq=%d ts=%d code=%d err=%v", remote, scope, h.SeqNum, h.Timestamp, code, err)
		if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
			log.Warnf("[TGS] write replay response failed remote=%s code=%d err=%v", remote, code, writeErr)
		}
		return
	}
	log.Debugf("[TGS] replay check passed remote=%s scope=%s seq=%d ts=%d", remote, scope, h.SeqNum, h.Timestamp)
	respType, respPayload, respErr := s.handleTGSReq(h, payload, peerADc)
	if respErr != nil {
		code := krb.CodeFromError(respErr)
		log.Warnf("[TGS] TGS_REQ handling failed remote=%s seq=%d code=%d err=%v", remote, h.SeqNum, code, respErr)
		if writeErr := s.writeError(conn, s.nextServerSeq(), code); writeErr != nil {
			log.Warnf("[TGS] write TGS_REQ error response failed remote=%s code=%d err=%v", remote, code, writeErr)
		}
		return
	}
	if err := krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload); err != nil {
		log.Errorf("[TGS] write response failed remote=%s msg_type=%d err=%v", remote, respType, err)
		return
	}
	log.Infof("[TGS] TGS response sent remote=%s req_seq=%d msg_type=%d payload_bytes=%d", remote, h.SeqNum, respType, len(respPayload))
}

func (s *Service) handleTGSReq(h krb.ProtocolHeader, payload []byte, peerADc uint32) (uint8, []byte, error) {
	req, err := krb.ParseTGSReqPayload(payload)
	if err != nil {
		log.Warnf("[TGS] parse TGS_REQ failed seq=%d payload_bytes=%d err=%v", h.SeqNum, len(payload), err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	idV := string(req.IDV.Data)
	log.Infof("[TGS] TGS_REQ received id_v=%s seq=%d ts=%d peer_adc=%d", idV, h.SeqNum, h.Timestamp, peerADc)
	ticket, err := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if err != nil {
		log.Warnf("[TGS] decode TGT failed id_v=%s seq=%d err=%v", idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	clientID := string(ticket.IDClient.Data)
	if ticket.IDTGS.Len > 0 && string(ticket.IDTGS.Data) != s.state.IDTGS {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		log.Warnf("[TGS] TGT rejected wrong id_tgs=%s expected=%s client=%s seq=%d code=%d", string(ticket.IDTGS.Data), s.state.IDTGS, clientID, h.SeqNum, krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}
	//检查票据是否过期，过期的票据不能被接受
	expire := ticket.TS2 + ticket.Lifetime
	if uint32(time.Now().Unix()) > expire {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		log.Warnf("[TGS] TGT expired client=%s id_v=%s seq=%d expire=%d code=%d", clientID, idV, h.SeqNum, expire, krb.ErrTicketExpired)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	//使用AS发来Ticket中的K_c_tgs解密TGS请求中的Authenticator
	//验证其中的客户端ID和ADc字段是否与票据中的一致，并且ADc字段如果不为0还要与客户端的IP地址匹配
	auth, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticket.KeyCTGS)
	if err != nil {
		log.Warnf("[TGS] decode authenticator failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if string(auth.IDClient.Data) != clientID {
		err := krb.ErrorFromCode(krb.ErrAuthMismatch)
		log.Warnf("[TGS] authenticator client mismatch auth_client=%s ticket_client=%s id_v=%s seq=%d code=%d", string(auth.IDClient.Data), clientID, idV, h.SeqNum, krb.ErrAuthMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrAuthMismatch), err
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc && auth.ADc != peerADc {
		err := krb.ErrorFromCode(krb.ErrADMismatch)
		log.Warnf("[TGS] authenticator address mismatch client=%s id_v=%s auth_adc=%d ticket_adc=%d peer_adc=%d seq=%d code=%d", clientID, idV, auth.ADc, ticket.ADc, peerADc, h.SeqNum, krb.ErrADMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrADMismatch), err
	}
	secret, ok := s.state.Services[idV]
	if !ok {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		log.Warnf("[TGS] TGS_REQ rejected unknown service client=%s id_v=%s seq=%d code=%d", clientID, idV, h.SeqNum, krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}

	//为客户端生成一个新的随机密钥 K_c_v，用于客户端与目标服务之间的通信。
	//这个密钥将被包含在发给客户端的票据中，并且也会在 TGS-REP 的加密部分中发送给客户端。
	keyCV, err := rand8()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrKeyDerive)
		log.Errorf("[TGS] generate K_c_v failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrKeyDerive), err
	}
	ts4 := uint32(time.Now().Unix())
	ticketVPlain, err := krb.BuildTicketVPlain(clientID, ticket.ADc, idV, keyCV, ts4, s.Config.TicketLifetimeSec)
	if err != nil {
		log.Warnf("[TGS] build service ticket failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(secret.Kv, ticketVPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[TGS] encrypt service ticket failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, idV, ts4, s.Config.TicketLifetimeSec, ticketVCipher)
	if err != nil {
		log.Warnf("[TGS] build TGS_REP plain failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	encPart, err := cryptoutil.EncryptDESCBC(ticket.KeyCTGS, innerPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[TGS] encrypt TGS_REP failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	resp, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		log.Warnf("[TGS] build TGS_REP payload failed client=%s id_v=%s seq=%d err=%v", clientID, idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	log.Infof("[TGS] service ticket issued client=%s id_v=%s seq=%d ts4=%d lifetime=%d payload_bytes=%d", clientID, idV, h.SeqNum, ts4, s.Config.TicketLifetimeSec, len(resp))
	return krb.MsgTGSRep, resp, nil
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	remote := "<nil>"
	if conn != nil {
		remote = conn.RemoteAddr().String()
	}
	err := krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[TGS] error response send failed remote=%s seq=%d code=%d err=%v", remote, seq, code, err)
		return err
	}
	log.Warnf("[TGS] error response sent remote=%s seq=%d code=%d", remote, seq, code)
	return nil
}

func rand8() ([8]byte, error) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
