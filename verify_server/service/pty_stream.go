package service

import (
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

// streamPTYOutput 负责持续从当前会话的PTY中读取输出数据，并将其封装成APP消息发送给客户端，直到PTY会话结束或发生错误为止。
// 它通过一个通道来接收PTY输出数据，并在每次读取到数据时构建一个APP响应消息并发送给客户端。如果PTY会话正常结束，它还会发送一个ptyEventExit事件通知客户端会话已结束。
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
