package service

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
	"security-project/verify_server/service/pty"
)

type appOperationContext struct {
	plain      krb.APPReqPlain
	current    *SessionContext
	sendPacket func(uint8, uint32, []byte) error
	respSeq    uint32
	nextSeq    func() uint32
}

type appOperation interface {
	appOperation()
}

type appOpenSSHRequest struct {
	targetID string
	term     string
	cols     uint16
	rows     uint16
	err      error
}

type appInputRequest struct {
	payload []byte
}

type appResizeRequest struct {
	cols uint16
	rows uint16
	err  error
}

type appSignalRequest struct {
	signal uint8
	err    error
}

type appCloseRequest struct{}

type appInvalidRequest struct {
	op uint8
}

func (appOpenSSHRequest) appOperation() {}
func (appInputRequest) appOperation()   {}
func (appResizeRequest) appOperation()  {}
func (appSignalRequest) appOperation()  {}
func (appCloseRequest) appOperation()   {}
func (appInvalidRequest) appOperation() {}

type appOperationFactory func(krb.APPReqPlain) appOperation

type appOperationHandler interface {
	Handle(*Service, appOperationContext, appOperation) (uint8, []byte, error)
}

type appOperationHandlerFactory func() appOperationHandler

var (
	appOperationFactories        = map[uint8]appOperationFactory{}
	appOperationHandlerFactories = map[reflect.Type]appOperationHandlerFactory{}
)

func init() {
	registerAPPOperation(pty.OpOpenSSH, appOpenSSHRequest{}, newAppOpenSSHRequest, func() appOperationHandler {
		return appOpenSSHHandler{}
	})
	registerAPPOperation(pty.OpInput, appInputRequest{}, newAppInputRequest, func() appOperationHandler {
		return appInputHandler{}
	})
	registerAPPOperation(pty.OpResize, appResizeRequest{}, newAppResizeRequest, func() appOperationHandler {
		return appResizeHandler{}
	})
	registerAPPOperation(pty.OpSignal, appSignalRequest{}, newAppSignalRequest, func() appOperationHandler {
		return appSignalHandler{}
	})
	registerAPPOperation(pty.OpClose, appCloseRequest{}, newAppCloseRequest, func() appOperationHandler {
		return appCloseHandler{}
	})
	registerAPPHandler(appInvalidRequest{}, func() appOperationHandler {
		return appInvalidHandler{}
	})
}

func registerAPPOperation(op uint8, prototype appOperation, operationFactory appOperationFactory, handlerFactory appOperationHandlerFactory) {
	appOperationFactories[op] = operationFactory
	registerAPPHandler(prototype, handlerFactory)
}

func registerAPPHandler(prototype appOperation, handlerFactory appOperationHandlerFactory) {
	appOperationHandlerFactories[reflect.TypeOf(prototype)] = handlerFactory
}

func newAppOpenSSHRequest(plain krb.APPReqPlain) appOperation {
	targetID, term, cols, rows, err := pty.ParseOpenSSHPayload(plain.Payload)
	return appOpenSSHRequest{targetID: targetID, term: term, cols: cols, rows: rows, err: err}
}

func newAppInputRequest(plain krb.APPReqPlain) appOperation {
	return appInputRequest{payload: plain.Payload}
}

func newAppResizeRequest(plain krb.APPReqPlain) appOperation {
	cols, rows, err := pty.ParseResizePayload(plain.Payload)
	return appResizeRequest{cols: cols, rows: rows, err: err}
}

func newAppSignalRequest(plain krb.APPReqPlain) appOperation {
	sig, err := pty.ParseSignalPayload(plain.Payload)
	return appSignalRequest{signal: sig, err: err}
}

func newAppCloseRequest(krb.APPReqPlain) appOperation {
	return appCloseRequest{}
}

func newAPPOperation(plain krb.APPReqPlain) appOperation {
	factory := appOperationFactories[plain.PtyOp]
	if factory == nil {
		return appInvalidRequest{op: plain.PtyOp}
	}
	return factory(plain)
}

func (s *Service) dispatchAPPOperation(ctx appOperationContext) (uint8, []byte, error) {
	operation := newAPPOperation(ctx.plain)
	handlerFactory := appOperationHandlerFactories[reflect.TypeOf(operation)]
	if handlerFactory == nil {
		log.Warnf("[V] APP operation handler missing client=%s op_type=%T", ctx.current.IDClient, operation)
		return krb.MsgApp, s.buildAPPRep(ctx.current, ctx.respSeq, pty.EventError, ctx.current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrorFromCode(krb.ErrMsgTypeInvalid)
	}
	return handlerFactory().Handle(s, ctx, operation)
}

type appOpenSSHHandler struct{}

func (appOpenSSHHandler) Handle(s *Service, ctx appOperationContext, operation appOperation) (uint8, []byte, error) {
	req := operation.(appOpenSSHRequest)
	current := ctx.current
	if req.err != nil {
		log.Warnf("[V] ssh open payload parse failed client=%s err=%v", current.IDClient, req.err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad ssh open payload")), req.err
	}
	if req.term == "" {
		req.term = s.Config.PTYDefaultTerm
	}
	target, err := s.lookupSSHTarget(req.targetID)
	if err != nil {
		log.Warnf("[V] ssh target lookup failed client=%s target=%s err=%v", current.IDClient, req.targetID, err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh target not found")), err
	}
	if err := checkTargetPermission(current.IDClient, target); err != nil {
		log.Warnf("[V] ssh target permission denied client=%s target=%s err=%v", current.IDClient, req.targetID, err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh target denied")), err
	}
	if current.PTY != nil {
		s.cleanupPTY(current, "replace ssh pty")
	}
	sshSession, startErr := pty.StartSSHSession(target, req.term, req.cols, req.rows)
	if startErr != nil || sshSession == nil {
		if startErr == nil {
			startErr = krb.ErrorFromCode(krb.ErrSessionNotFound)
		}
		log.Errorf("[V] ssh pty start failed client=%s target=%s host=%s:%d user=%s term=%s cols=%d rows=%d err=%v", current.IDClient, target.ID, target.Host, target.Port, target.SSHUser, req.term, req.cols, req.rows, startErr)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("ssh pty start failed")), startErr
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
		NextSeq:    ctx.nextSeq,
		SendPacket: ctx.sendPacket,
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
	log.Infof("[V] ssh pty opened client=%s target=%s host=%s user=%s pty_session_id=%d term=%s cols=%d rows=%d", current.IDClient, current.TargetID, current.TargetHost, current.SSHUser, current.PtySessionID, req.term, req.cols, req.rows)
	return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventOpenOK, current.PtySessionID, -1, out), nil
}

type appInputHandler struct{}

func (appInputHandler) Handle(s *Service, ctx appOperationContext, operation appOperation) (uint8, []byte, error) {
	req := operation.(appInputRequest)
	current := ctx.current
	if current.PTY == nil {
		log.Warnf("[V] pty input rejected not open client=%s", current.IDClient)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
	}
	if _, err := current.PTY.Write(req.payload); err != nil {
		log.Warnf("[V] pty input write failed client=%s payload_bytes=%d err=%v", current.IDClient, len(req.payload), err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty write failed")), krb.ErrorFromCode(krb.ErrSocketSend)
	}
	log.Infof("[V] pty input accepted client=%s pty_session_id=%d payload_bytes=%d", current.IDClient, current.PtySessionID, len(req.payload))
	return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventOutput, current.PtySessionID, -1, []byte{}), nil
}

type appResizeHandler struct{}

func (appResizeHandler) Handle(s *Service, ctx appOperationContext, operation appOperation) (uint8, []byte, error) {
	req := operation.(appResizeRequest)
	current := ctx.current
	if current.PTY == nil {
		log.Warnf("[V] pty resize rejected not open client=%s", current.IDClient)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
	}
	if req.err != nil {
		log.Warnf("[V] pty resize payload parse failed client=%s err=%v", current.IDClient, req.err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad resize payload")), req.err
	}
	if err := current.PTY.Resize(req.cols, req.rows); err != nil {
		log.Warnf("[V] pty resize failed client=%s cols=%d rows=%d err=%v", current.IDClient, req.cols, req.rows, err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("resize failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
	}
	log.Infof("[V] pty resized client=%s pty_session_id=%d cols=%d rows=%d", current.IDClient, current.PtySessionID, req.cols, req.rows)
	return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventOutput, current.PtySessionID, -1, []byte("")), nil
}

type appSignalHandler struct{}

func (appSignalHandler) Handle(s *Service, ctx appOperationContext, operation appOperation) (uint8, []byte, error) {
	req := operation.(appSignalRequest)
	current := ctx.current
	if current.PTY == nil {
		log.Warnf("[V] pty signal rejected not open client=%s", current.IDClient)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("pty not open")), krb.ErrorFromCode(krb.ErrSessionNotFound)
	}
	if req.err != nil {
		log.Warnf("[V] pty signal payload parse failed client=%s err=%v", current.IDClient, req.err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("bad signal payload")), req.err
	}
	if err := current.PTY.Signal(req.signal); err != nil {
		log.Warnf("[V] pty signal failed client=%s signal=%d err=%v", current.IDClient, req.signal, err)
		return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventError, current.PtySessionID, -1, []byte("signal failed")), krb.ErrorFromCode(krb.ErrSessionNotFound)
	}
	log.Infof("[V] pty signal sent client=%s pty_session_id=%d signal=%d", current.IDClient, current.PtySessionID, req.signal)
	return krb.MsgApp, s.buildAPPRep(current, ctx.respSeq, pty.EventOutput, current.PtySessionID, -1, []byte("signal ok")), nil
}

type appCloseHandler struct{}

func (appCloseHandler) Handle(s *Service, ctx appOperationContext, _ appOperation) (uint8, []byte, error) {
	current := ctx.current
	ptySessionID := current.PtySessionID
	resp := s.buildAPPRep(current, ctx.respSeq, pty.EventExit, ptySessionID, 0, []byte("bye"))
	s.cleanupPTY(current, "pty close")
	log.Infof("[V] pty session closed client=%s pty_session_id=%d total_frames=%d", current.IDClient, ptySessionID, atomic.LoadUint64(&current.TotalFrames))
	return krb.MsgApp, resp, nil
}

type appInvalidHandler struct{}

func (appInvalidHandler) Handle(s *Service, ctx appOperationContext, operation appOperation) (uint8, []byte, error) {
	req := operation.(appInvalidRequest)
	log.Warnf("[V] invalid pty operation client=%s op=%d", ctx.current.IDClient, req.op)
	return krb.MsgApp, s.buildAPPRep(ctx.current, ctx.respSeq, pty.EventError, ctx.current.PtySessionID, -1, []byte("invalid pty op")), krb.ErrorFromCode(krb.ErrMsgTypeInvalid)
}
