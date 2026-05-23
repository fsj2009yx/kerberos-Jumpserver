//go:build windows

package pty

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

func StartSession(shell, term string, cols, rows uint16) (*Session, error) {
	if shell == "" {
		return nil, fmt.Errorf("pty shell is empty")
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM="+term)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	_ = stdin
	_ = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Session{PTY: &windowsPTY{r: stdout, w: stdin}, Cmd: cmd}, nil
}

type windowsPTY struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (p *windowsPTY) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *windowsPTY) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *windowsPTY) Close() error {
	_ = p.w.Close()
	return p.r.Close()
}

func (p *Session) Resize(cols, rows uint16) error {
	if p != nil && p.ResizeFn != nil {
		return p.ResizeFn(cols, rows)
	}
	return fmt.Errorf("resize unsupported on windows fallback")
}

func (p *Session) Signal(sig uint8) error {
	if p != nil && p.SignalFn != nil {
		return p.SignalFn(sig)
	}
	if p == nil || p.Cmd == nil || p.Cmd.Process == nil {
		return fmt.Errorf("pty process not started")
	}
	var s syscall.Signal
	switch sig {
	case 1:
		s = syscall.CTRL_C_EVENT
	case 2:
		s = syscall.CTRL_BREAK_EVENT
	case 3:
		s = syscall.Signal(1)
	default:
		s = syscall.CTRL_BREAK_EVENT
	}
	return p.Cmd.Process.Signal(s)
}

func (p *Session) Close() error {
	if p == nil {
		return nil
	}
	if p.CloseFn != nil {
		_ = p.CloseFn()
		p.CloseFn = nil
	}
	if p.Writer != nil {
		_ = p.Writer.Close()
		p.Writer = nil
	}
	if p.PTY != nil {
		_ = p.PTY.Close()
	}
	if p.Cmd != nil && p.Cmd.Process != nil {
		_ = p.Cmd.Process.Kill()
		_, _ = p.Cmd.Process.Wait()
	}
	return nil
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
