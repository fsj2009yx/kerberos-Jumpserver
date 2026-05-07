package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

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
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic(fmt.Sprintf("load config: %v", err))
	}
	//加载 TGS 密钥 k_tgs，解密AS发来的Ticket
	ktgs, err := krb.LoadConfiguredKey8(cfg.KTGSPath, cfg.KTGSHex, "tgs k_tgs")
	if err != nil {
		panic(fmt.Sprintf("load k_tgs: %v", err))
	}
	st := &krb.TGSState{
		Ktgs:     ktgs,
		IDTGS:    "TGS",
		Services: make(map[string]krb.ServiceSecret, len(cfg.ServiceDB)),
	}
	for _, s := range cfg.ServiceDB {
		//加载服务密钥 k_v，用于加密发给客户端的票据和 TGS-REP 中的认证数据
		kv, err := krb.LoadConfiguredKey8(s.KVPath, s.KVHex, "service "+s.IDV+" k_v")
		if err != nil {
			panic(fmt.Sprintf("load service key %s: %v", s.IDV, err))
		}
		st.Services[s.IDV] = krb.ServiceSecret{IDV: s.IDV, Kv: kv}
	}
	return &Service{
		Config:    cfg,
		state:     st,
		replay:    krb.NewReplayWindow(cfg.AntiReplayWindow),
		startTime: time.Now(),
	}
}

func (s *Service) Run() error {
	if s.Config.WebUIPort > 0 {
		go s.runWebUI()
	}
	addr := net.JoinHostPort(s.Config.ListenHost, fmt.Sprintf("%d", s.Config.ListenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("[TGS] listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TGS] accept failed: %v", err)
			continue
		}
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
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	peerADc := krb.PeerIP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.Config.ReadTimeoutSec) * time.Second))
	h, payload, err := krb.ReadPacket(conn, s.Config.MaxPayloadBytes)
	if err != nil {
		code := krb.CodeFromError(err)
		if code != krb.ErrSocketRecv {
			_ = s.writeError(conn, s.nextServerSeq(), code)
		}
		return
	}
	if err := krb.CheckHeaderType(h.MsgType, krb.MsgTGSReq); err != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(err))
		return
	}
	scope, err := s.replayScopeForTGS(payload)
	if err != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(err))
		return
	}
	if err := s.replay.CheckScoped(scope, h.Timestamp, h.SeqNum); err != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(err))
		return
	}
	respType, respPayload, respErr := s.handleTGSReq(h, payload, peerADc)
	if respErr != nil {
		_ = s.writeError(conn, s.nextServerSeq(), krb.CodeFromError(respErr))
		return
	}
	_ = krb.WritePacket(conn, respType, s.nextServerSeq(), uint32(time.Now().Unix()), respPayload)
}

func (s *Service) handleTGSReq(h krb.ProtocolHeader, payload []byte, peerADc uint32) (uint8, []byte, error) {
	req, err := krb.ParseTGSReqPayload(payload)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	ticket, err := krb.DecodeTicketTGS(req.TicketTGS, s.state.Ktgs)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if ticket.IDTGS.Len > 0 && string(ticket.IDTGS.Data) != s.state.IDTGS {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}
	//检查票据是否过期，过期的票据不能被接受
	expire := ticket.TS2 + ticket.Lifetime
	if uint32(time.Now().Unix()) > expire {
		err := krb.ErrorFromCode(krb.ErrTicketExpired)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketExpired), err
	}

	//使用AS发来Ticket中的K_c_tgs解密TGS请求中的Authenticator
	//验证其中的客户端ID和ADc字段是否与票据中的一致，并且ADc字段如果不为0还要与客户端的IP地址匹配
	auth, err := krb.DecodeAuthenticatorCTGS(req.AuthCipher, ticket.KeyCTGS)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	if string(auth.IDClient.Data) != string(ticket.IDClient.Data) {
		err := krb.ErrorFromCode(krb.ErrAuthMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrAuthMismatch), err
	}
	if auth.ADc != 0 && ticket.ADc != 0 && auth.ADc != ticket.ADc && auth.ADc != peerADc {
		err := krb.ErrorFromCode(krb.ErrADMismatch)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrADMismatch), err
	}
	secret, ok := s.state.Services[string(req.IDV.Data)]
	if !ok {
		err := krb.ErrorFromCode(krb.ErrTicketInvalid)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrTicketInvalid), err
	}

	//为客户端生成一个新的随机密钥 K_c_v，用于客户端与目标服务之间的通信。
	//这个密钥将被包含在发给客户端的票据中，并且也会在 TGS-REP 的加密部分中发送给客户端。
	keyCV, err := rand8()
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrKeyDerive)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrKeyDerive), err
	}
	ts4 := uint32(time.Now().Unix())
	ticketVPlain, err := krb.BuildTicketVPlain(string(ticket.IDClient.Data), ticket.ADc, string(req.IDV.Data), keyCV, ts4, s.Config.TicketLifetimeSec)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	ticketVCipher, err := cryptoutil.EncryptDESCBC(secret.Kv, ticketVPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	innerPlain, err := krb.BuildTGSRepPlain(keyCV, string(req.IDV.Data), ts4, s.Config.TicketLifetimeSec, ticketVCipher)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	encPart, err := cryptoutil.EncryptDESCBC(ticket.KeyCTGS, innerPlain)
	if err != nil {
		err := krb.ErrorFromCode(krb.ErrDESPadding)
		return krb.MsgErr, krb.BuildErrorPayload(krb.ErrDESPadding), err
	}
	resp, err := krb.BuildASRepPayload(encPart)
	if err != nil {
		return krb.MsgErr, krb.BuildErrorPayload(krb.CodeFromError(err)), err
	}
	return krb.MsgTGSRep, resp, nil
}

func (s *Service) writeError(conn net.Conn, seq uint32, code int32) error {
	return krb.WritePacket(conn, krb.MsgErr, seq, uint32(time.Now().Unix()), krb.BuildErrorPayload(code))
}

func rand8() ([8]byte, error) {
	var out [8]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
