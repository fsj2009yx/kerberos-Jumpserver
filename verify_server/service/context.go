package service

import (
	"context"
	"sync"
	"time"

	"security-project/verify_server/service/pty"
)

type SessionContext struct {
	IDClient     string
	ADc          uint32
	KeyCV        [8]byte
	ExpireAt     uint32
	PtySessionID uint32
	LastIO       time.Time
	TotalFrames  uint64
	PTY          *pty.Session
	Ctx          context.Context
	Cancel       context.CancelFunc
	Closed       bool
}

type VState struct {
	IDV      string
	Kv       [8]byte
	Sessions map[string]*SessionContext
	mu       sync.RWMutex
}
