package pty

import (
	"io"
	"os"
	"os/exec"
	"sync"
)

type Session struct {
	PTY      io.ReadWriteCloser
	Reader   io.Reader
	Writer   io.WriteCloser
	File     *os.File
	Cmd      *exec.Cmd
	ResizeFn func(cols, rows uint16) error
	SignalFn func(sig uint8) error
	CloseFn  func() error
	mu       sync.Mutex
}

func (p *Session) Write(data []byte) (int, error) {
	if p.Writer != nil {
		return p.Writer.Write(data)
	}
	return p.PTY.Write(data)
}
