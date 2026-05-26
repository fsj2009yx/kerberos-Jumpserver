package pty

import (
	"fmt"
	"io"
	"sync"
)

type Session struct {
	PTY      io.ReadWriteCloser
	Reader   io.Reader
	Writer   io.WriteCloser
	ResizeFn func(cols, rows uint16) error
	SignalFn func(sig uint8) error
	CloseFn  func() error
	mu       sync.Mutex
}

func (p *Session) Write(data []byte) (int, error) {
	if p == nil {
		return 0, fmt.Errorf("pty not started")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Writer != nil {
		return p.Writer.Write(data)
	}
	if p.PTY == nil {
		return 0, fmt.Errorf("pty not started")
	}
	return p.PTY.Write(data)
}

func (p *Session) Resize(cols, rows uint16) error {
	if p == nil {
		return fmt.Errorf("pty not started")
	}
	if p.ResizeFn == nil {
		return fmt.Errorf("pty resize unsupported")
	}
	return p.ResizeFn(cols, rows)
}

func (p *Session) Signal(sig uint8) error {
	if p == nil {
		return fmt.Errorf("pty process not started")
	}
	if p.SignalFn == nil {
		return fmt.Errorf("pty signal unsupported")
	}
	return p.SignalFn(sig)
}

func (p *Session) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var err error
	if p.CloseFn != nil {
		err = p.CloseFn()
		p.CloseFn = nil
	}
	if p.Writer != nil {
		_ = p.Writer.Close()
		p.Writer = nil
	}
	if p.PTY != nil {
		if closeErr := p.PTY.Close(); err == nil {
			err = closeErr
		}
		p.PTY = nil
	}
	return err
}

func (p *Session) ReadAll(dst chan<- []byte, stop <-chan struct{}) {
	if p == nil {
		close(dst)
		return
	}
	defer close(dst)
	reader := p.Reader
	if reader == nil {
		reader = p.PTY
	}
	if reader == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case dst <- chunk:
			case <-stop:
				return
			}
		}
		if err != nil {
			return
		}
	}
}
