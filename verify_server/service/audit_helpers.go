package service

import (
	"encoding/base64"
	"fmt"

	"security-project/pkg/utils/log"
	"security-project/verify_server/service/audit/model"
)

type AuditRecord = model.Record

func auditPayload(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func auditSessionID(clientID string, ptySessionID uint32) string {
	if ptySessionID == 0 {
		return clientID
	}
	return fmt.Sprintf("%s:%d", clientID, ptySessionID)
}

func auditPTYOpName(op uint8) string {
	switch op {
	case 0x01:
		return "unsupported_open"
	case 0x02:
		return "input"
	case 0x03:
		return "resize"
	case 0x04:
		return "signal"
	case 0x05:
		return "close"
	case 0x06:
		return "open_ssh"
	default:
		return fmt.Sprintf("op_%d", op)
	}
}

func auditPTYEventName(event uint8) string {
	switch event {
	case 0x11:
		return "open_ok"
	case 0x12:
		return "output"
	case 0x13:
		return "exit"
	case 0x14:
		return "error"
	default:
		return fmt.Sprintf("event_%d", event)
	}
}

func (s *Service) appendAudit(rec AuditRecord) {
	if s == nil || s.audit == nil {
		return
	}
	if err := s.audit.Append(rec); err != nil {
		log.Warnf("[V] audit append failed kind=%s event=%s client=%s err=%v", rec.Kind, rec.EventType, rec.ClientID, err)
	}
}
