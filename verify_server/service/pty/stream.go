package pty

import (
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

type StreamCallbacks struct {
	ClientID     string
	SessionID    uint32
	Done         <-chan struct{}
	NextSeq      func() uint32
	SendPacket   func(uint8, uint32, []byte) error
	BuildPayload func(seq uint32, event uint8, sessionID uint32, exitCode int32, payload []byte) []byte
	OnFrame      func()
	OnIO         func(time.Time)
	IsClosed     func() bool
}

func StreamOutput(session *Session, callbacks StreamCallbacks) {
	if session == nil || callbacks.Done == nil {
		log.Warnf("[V] pty output stream skipped due to invalid session")
		return
	}
	log.Infof("[V] pty output stream started client=%s pty_session_id=%d", callbacks.ClientID, callbacks.SessionID)
	ch := make(chan []byte, 16)
	go session.ReadAll(ch, callbacks.Done)
	for data := range ch {
		if len(data) == 0 {
			continue
		}
		callbacks.OnFrame()
		callbacks.OnIO(time.Now())
		seq := callbacks.NextSeq()
		rep := callbacks.BuildPayload(seq, EventOutput, callbacks.SessionID, -1, data)
		if err := callbacks.SendPacket(krb.MsgApp, seq, rep); err != nil {
			log.Warnf("[V] pty output send failed client=%s seq=%d err=%v", callbacks.ClientID, seq, err)
			return
		}
	}
	if callbacks.IsClosed() {
		log.Infof("[V] pty output stream ended after close client=%s", callbacks.ClientID)
		return
	}
	seq := callbacks.NextSeq()
	rep := callbacks.BuildPayload(seq, EventExit, callbacks.SessionID, 0, nil)
	if err := callbacks.SendPacket(krb.MsgApp, seq, rep); err != nil {
		log.Warnf("[V] pty exit send failed client=%s seq=%d err=%v", callbacks.ClientID, seq, err)
		return
	}
	log.Infof("[V] pty output stream ended client=%s pty_session_id=%d", callbacks.ClientID, callbacks.SessionID)
}
