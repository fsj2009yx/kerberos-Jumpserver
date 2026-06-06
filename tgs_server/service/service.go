package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"security-project/common/krb/transport"
	"sync/atomic"
	"time"

	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
	"security-project/pkg/utils/log"
	"security-project/tgs_server/config"
)

type Service struct {
	Config        *config.Config
	state         *krb.TGSState
	startTime     time.Time
	ticketVIssued uint32
	httpServer    *http.Server
}

func NewService(configPath string) *Service {
	log.Infof("[TGS] initializing service config=%s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Errorf("[TGS] load config failed err=%v", err)
		panic(fmt.Sprintf("load config: %v", err))
	}
	//加载 TGS 密钥 k_tgs，解密AS发来的Ticket
	ktgs, err := cryptoutil.LoadConfiguredKey8(cfg.KTGSPath, cfg.KTGSHex, "tgs k_tgs")
	if err != nil {
		log.Errorf("[TGS] load k_tgs failed err=%v", err)
		panic(fmt.Sprintf("load k_tgs: %v", err))
	}
	st := &krb.TGSState{
		Ktgs:     ktgs,
		IDTGS:    "TGS",
		Services: make(map[string]krb.ServiceSecret, len(cfg.ServiceDB)),
	}
	for _, s := range cfg.ServiceDB {
		//加载服务密钥 k_v，用于加密发给客户端的票据和 TGS-REP 中的认证数据
		kv, err := cryptoutil.LoadConfiguredKey8(s.KVPath, s.KVHex, "service "+s.IDV+" k_v")
		if err != nil {
			log.Errorf("[TGS] load service key failed service=%s err=%v", s.IDV, err)
			panic(fmt.Sprintf("load service key %s: %v", s.IDV, err))
		}
		st.Services[s.IDV] = krb.ServiceSecret{IDV: s.IDV, Kv: kv}
		log.Infof("[TGS] service loaded service=%s addr=%s", s.IDV, s.Addr)
	}
	log.Infof("[TGS] service initialized services=%d ticket_lifetime=%d", len(st.Services), cfg.TicketLifetimeSec)
	return &Service{
		Config:    cfg,
		state:     st,
		startTime: time.Now(),
	}
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		log.Infof("[TGS] starting webui addr=%s:%d", s.Config.WebUIHost, s.Config.WebUIPort)
		go s.runWebUI()
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
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
			log.Errorf("[TGS] accept failed err=%v", err)
			continue
		}
		log.Infof("[TGS] accepted connection remote=%s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *Service) handleConnection(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	replay := krb.NewReplayWindow(s.Config.AntiReplayWindow)
	var sendSeq uint32
	nextConnSeq := func() uint32 {
		sendSeq++
		if sendSeq == 0 {
			sendSeq = 1
		}
		return sendSeq
	}
	defer func() {
		_ = conn.Close()
		log.Infof("[TGS] connection closed remote=%s", remote)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	peerADc := krb.PeerIP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadTimeoutSec) * time.Second))
	h, payload, err := transport.ReadPacket(conn, s.Config.MaxPayloadBytes)
	if err != nil {
		code := krb.CodeFromError(err)
		if code != krb.ErrSocketRecv {
			log.Warnf("[TGS] read packet failed remote=%s code=%s err=%v", remote, krb.FormatCode(code), err)
			_ = s.writeError(conn, nextConnSeq(), code)
		}
		return
	}
	log.Infof("[TGS] packet received remote=%s msg_type=%d seq=%d payload_bytes=%d", remote, h.MsgType, h.SeqNum, len(payload))
	if err := krb.CheckPacketType(h, payload, krb.MsgTGSReq); err != nil {
		code := krb.CodeFromError(err)
		if peerCode, ok := krb.PeerErrorCode(err); ok {
			log.Warnf("[TGS] peer error response received remote=%s seq=%d code=%s desc=%q", remote, h.SeqNum, krb.FormatCode(peerCode), krb.CodeDescription(peerCode))
			return
		}
		log.Warnf("[TGS] invalid message type remote=%s msg_type=%d code=%s err=%v", remote, h.MsgType, krb.FormatCode(code), err)
		_ = s.writeError(conn, nextConnSeq(), code)
		return
	}
	if err := replay.Check(h.Timestamp, h.SeqNum); err != nil {
		code := krb.CodeFromError(err)
		log.Warnf("[TGS] replay check failed remote=%s seq=%d code=%s err=%v", remote, h.SeqNum, krb.FormatCode(code), err)
		_ = s.writeError(conn, nextConnSeq(), code)
		return
	}
	respType, respPayload, respErr := s.handleTGSReq(h, payload, peerADc)
	if respErr != nil {
		code := krb.CodeFromError(respErr)
		log.Warnf("[TGS] TGS_REQ handling failed remote=%s seq=%d code=%s err=%v", remote, h.SeqNum, krb.FormatCode(code), respErr)
		_ = s.writeError(conn, nextConnSeq(), code)
		return
	}
	if err := transport.WritePacket(conn, respType, nextConnSeq(), uint32(time.Now().Unix()), respPayload); err != nil {
		log.Errorf("[TGS] write response failed remote=%s err=%v", remote, err)
		return
	}
	atomic.AddUint32(&s.ticketVIssued, 1)
	log.Infof("[TGS] TGS_REP sent remote=%s seq=%d payload_bytes=%d", remote, h.SeqNum, len(respPayload))
}

func (s *Service) handleTGSReq(h krb.ProtocolHeader, payload []byte, peerADc uint32) (uint8, []byte, error) {
	req, err := krb.ParseTGSReqPayload(payload)
	if err != nil {
		log.Warnf("[TGS] parse TGS_REQ failed seq=%d err=%v", h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	idV := string(req.IDV.Data)
	log.Infof("[TGS] TGS_REQ received id_v=%s seq=%d peer_adc=%d", idV, h.SeqNum, peerADc)
	ticket, err := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if err != nil {
		log.Warnf("[TGS] decode TGT failed id_v=%s seq=%d err=%v", idV, h.SeqNum, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	clientID := string(ticket.IDClient.Data)
	if ticket.IDTGS.Len > 0 && string(ticket.IDTGS.Data) != s.state.IDTGS {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		log.Warnf("[TGS] invalid TGT id_tgs=%s expected=%s client=%s", string(ticket.IDTGS.Data), s.state.IDTGS, clientID)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}
	//检查票据是否过期，过期的票据不能被接受
	expire := ticket.TS2 + ticket.Lifetime
	if uint32(time.Now().Unix()) > expire {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		log.Warnf("[TGS] TGT expired client=%s id_v=%s expire=%d", clientID, idV, expire)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	//使用AS发来Ticket中的K_c_tgs解密TGS请求中的Authenticator
	//验证其中的客户端ID和ADc字段是否与票据中的一致，并且ADc字段如果不为0还要与客户端的IP地址匹配
	auth, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticket.KeyCTGS)
	if err != nil {
		log.Warnf("[TGS] decode authenticator failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if string(auth.IDClient.Data) != clientID {
		err := krb.ErrorFromCode(krb.ErrAuthMismatch)
		log.Warnf("[TGS] auth mismatch auth_client=%s ticket_client=%s", string(auth.IDClient.Data), clientID)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrAuthMismatch), err
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc && auth.ADc != peerADc {
		err := krb.ErrorFromCode(krb.ErrADMismatch)
		log.Warnf("[TGS] address mismatch client=%s auth_adc=%d ticket_adc=%d peer_adc=%d", clientID, auth.ADc, ticket.ADc, peerADc)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrADMismatch), err
	}
	secret, ok := s.state.Services[idV]
	if !ok {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		log.Warnf("[TGS] service not found client=%s id_v=%s", clientID, idV)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}

	//为客户端生成一个新的随机密钥 K_c_v，用于客户端与目标服务之间的通信。
	//这个密钥将被包含在发给客户端的票据中，并且也会在 TGS-REP 的加密部分中发送给客户端。
	keyCV, err := rand8()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrKeyDerive)
		log.Errorf("[TGS] session key generation failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrKeyDerive), err
	}
	ts4 := uint32(time.Now().Unix())
	ticketVPlain, err := krb.BuildTicketVPlain(clientID, ticket.ADc, idV, keyCV, ts4, s.Config.TicketLifetimeSec)
	if err != nil {
		log.Warnf("[TGS] build service ticket failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}

	//Ticket票据加密
	ticketVCipher, err := cryptoutil.EncryptDESCBC(secret.Kv, ticketVPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[TGS] encrypt service ticket failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}

	//构建TGS明文
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, idV, ts4, s.Config.TicketLifetimeSec, ticketVCipher)
	if err != nil {
		log.Warnf("[TGS] build TGS_REP plain failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}

	//明文加密
	encPart, err := cryptoutil.EncryptDESCBC(ticket.KeyCTGS, innerPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		log.Errorf("[TGS] encrypt TGS_REP failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}

	//构建TGS-REP消息的加密部分
	resp, err := krb.BuildEncPack(encPart)
	if err != nil {
		log.Warnf("[TGS] build TGS_REP payload failed client=%s id_v=%s err=%v", clientID, idV, err)
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	log.Infof("[TGS] service ticket issued client=%s id_v=%s lifetime=%d", clientID, idV, s.Config.TicketLifetimeSec)
	return krb.MsgTGSRep, resp, nil
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	err := transport.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
	if err != nil {
		log.Errorf("[TGS] error response send failed seq=%d code=%s desc=%q err=%v", seq, krb.FormatCode(code), krb.CodeDescription(code), err)
		return err
	}
	log.Warnf("[TGS] error response sent seq=%d code=%s desc=%q", seq, krb.FormatCode(code), krb.CodeDescription(code))
	return nil
}

func rand8() ([8]byte, error) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
