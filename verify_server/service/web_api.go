package service

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	certutil "security-project/common/cert"
	"security-project/common/krb"
	"security-project/pkg/utils/log"
	auditrouter "security-project/verify_server/service/audit/router"
)

func (s *Service) runWebUI() {
	engine := auditrouter.New(s.audit, s)
	addr := net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort))
	log.Infof("[V] gin webui listening addr=%s", addr)
	if err := engine.Run(addr); err != nil {
		log.Errorf("[V] gin webui failed addr=%s err=%v", addr, err)
	}
}

// Status 返回服务的当前状态信息，包括节点ID、运行时间、活跃会话数等。
func (s *Service) Status() map[string]any {
	s.state.mu.RLock()
	activeKerberos := len(s.state.Sessions)
	activePTY := 0
	for _, sess := range s.state.Sessions {
		if sess.PTY != nil && !sess.Closed.Load() {
			activePTY++
		}
	}
	s.state.mu.RUnlock()
	return map[string]any{
		"node_id":                  s.Config.NodeID,
		"uptime_s":                 int64(time.Since(s.startTime).Seconds()),
		"active_sessions":          activeKerberos,
		"active_kerberos_sessions": activeKerberos,
		"active_pty_sessions":      activePTY,
		"total_pty_frames":         atomic.LoadUint64(&s.ptyFrames),
		"total_rejected_frames":    0,
	}
}

// Sessions 返回当前所有活跃的Kerberos会话信息
func (s *Service) Sessions() []map[string]any {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	out := make([]map[string]any, 0, len(s.state.Sessions))
	for _, sess := range s.state.Sessions {
		sum := krb.Hash256(sess.KeyCV[:])
		out = append(out, map[string]any{
			"client_id":       sess.IDClient,
			"client_addr":     sess.ClientAddr,
			"target_id":       sess.TargetID,
			"target_host":     sess.TargetHost,
			"ssh_user":        sess.SSHUser,
			"k_cv_sha256":     hex.EncodeToString(sum[:8]),
			"expire_at":       sess.ExpireAt,
			"last_io_ts":      sess.LastIO.Unix(),
			"total_frames":    sess.TotalFrames,
			"pty_session_id":  sess.PtySessionID,
			"kerberos_active": true,
			"pty_active":      sess.PTY != nil && !sess.Closed.Load(),
		})
	}
	return out
}

func (s *Service) Certificate(id string) (any, error) {
	cert := s.clientCerts[id]
	if cert == nil {
		return nil, fmt.Errorf("certificate not found: %s", id)
	}
	return cert, nil
}

func (s *Service) VerifyCertificate(id string) (map[string]any, int) {
	cert := s.clientCerts[id]
	if cert == nil {
		return map[string]any{"error": fmt.Sprintf("certificate not found: %s", id)}, 404
	}
	if err := certutil.CertVerify(cert); err != nil {
		return map[string]any{"id": id, "result": "fail", "reason": err.Error()}, 200
	}
	result := "ok"
	reason := ""
	if cert.ID != id {
		result = "fail"
		reason = "certificate id mismatch"
	}
	return map[string]any{"id": id, "result": result, "reason": reason}, 200
}
