package pty

import (
	"io"
	"os"
	"os/exec"
	"sync"
)

type Session struct {
	PTY  io.ReadWriteCloser
	File *os.File
	Cmd  *exec.Cmd
	mu   sync.Mutex
}

func (p *Session) Write(data []byte) (int, error) {
	return p.PTY.Write(data)
}
