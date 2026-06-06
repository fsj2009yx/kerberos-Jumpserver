package pty

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"security-project/verify_server/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func StartSSHSession(target config.SSHTarget, term string, cols, rows uint16) (*Session, error) {
	auth, err := sshAuthMethod(target)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(term) == "" {
		term = "xterm-256color"
	}
	hostPort := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	// 获取 SSH 主机密钥回调函数，确保在连接 SSH 服务器时能够验证服务器的身份，防止中间人攻击等安全风险。
	hostKeyCallback, err := sshHostKeyCallback(target)
	if err != nil {
		return nil, err
	}
	clientConfig := &ssh.ClientConfig{
		User:            target.SSHUser,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", hostPort, clientConfig)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	//创建ssh Session，并启动输入输出流
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, err
	}

	reader, closeReader := mergeReaders(stdout, stderr)
	closeOnce := sync.Once{}
	closeAll := func() error {
		var closeErr error
		closeOnce.Do(func() {
			_ = stdin.Close()
			_ = session.Close()
			_ = client.Close()
			closeErr = closeReader()
		})
		return closeErr
	}

	go func() {
		_ = session.Wait()
		_ = closeReader()
	}()

	return &Session{
		Reader: reader,
		Writer: stdin,
		ResizeFn: func(cols, rows uint16) error {
			return session.WindowChange(int(rows), int(cols))
		},
		SignalFn: func(sig uint8) error {
			return session.Signal(sshSignal(sig))
		},
		CloseFn: closeAll,
	}, nil
}

func sshHostKeyCallback(target config.SSHTarget) (ssh.HostKeyCallback, error) {
	if strings.TrimSpace(target.KnownHostsPath) == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	return knownhosts.New(target.KnownHostsPath)
}

func sshAuthMethod(target config.SSHTarget) (ssh.AuthMethod, error) {
	switch target.AuthType {
	case "", "private_key":
		key, err := os.ReadFile(target.KeyPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(signer), nil
	case "password":
		if target.Password != "" {
			return ssh.Password(target.Password), nil
		}
		raw, err := os.ReadFile(target.PasswordPath)
		if err != nil {
			return nil, err
		}
		return ssh.Password(strings.TrimRight(string(raw), "\r\n")), nil
	default:
		return nil, fmt.Errorf("unsupported ssh auth_type: %s", target.AuthType)
	}
}

// sshSignal 将 uint8 类型的信号转换为 ssh.Signal 类型，以便在 SSH 会话中发送信号给远程服务器
// 它根据输入的信号值返回对应的 SSH 信号字符串
func sshSignal(sig uint8) ssh.Signal {
	switch sig {
	case 1:
		return ssh.Signal("INT")
	case 2:
		return ssh.Signal("TERM")
	case 3:
		return ssh.Signal("KILL")
	default:
		return ssh.Signal("TERM")
	}
}

// mergeReaders 作用是将多个 io.Reader 合并成一个 io.Reader
// 它使用 io.Pipe 创建一个管道，并启动一个 goroutine 来复制每个 reader 的内容到管道的写端。当所有 reader 都完成后，管道的写端会被关闭，从而通知读取者没有更多数据可读。
func mergeReaders(readers ...io.Reader) (io.Reader, func() error) {
	pr, pw := io.Pipe()
	var wg sync.WaitGroup
	for _, reader := range readers {
		if reader == nil {
			continue
		}
		wg.Add(1)
		go func(r io.Reader) {
			defer wg.Done()
			_, _ = io.Copy(pw, r)
		}(reader)
	}
	go func() {
		wg.Wait()
		_ = pw.Close()
	}()
	return pr, pr.Close
}
