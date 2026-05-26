package service

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/verify_server/service/pty"
)

type SessionContext struct {
	IDClient     string
	ClientAddr   string
	ADc          uint32
	KeyCV        [8]byte
	ExpireAt     uint32
	TargetID     string
	TargetHost   string
	SSHUser      string
	PtySessionID uint32
	LastIO       time.Time
	TotalFrames  uint64
	PTY          *pty.Session
	AppReplay    *krb.ReplayWindow
	Ctx          context.Context
	Cancel       context.CancelFunc
	Closed       atomic.Bool
}

type VState struct {
	IDV      string
	Kv       [8]byte
	Sessions map[string]*SessionContext
	mu       sync.RWMutex
}
