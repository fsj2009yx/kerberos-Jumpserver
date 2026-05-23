package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		activeKerberos := len(s.state.Sessions)
		activePTY := 0
		for _, sess := range s.state.Sessions {
			if sess.PTY != nil && !sess.Closed.Load() {
				activePTY++
			}
		}
		s.state.mu.RUnlock()
		writeJSONResponse(w, r, "[V]", "/api/status", map[string]any{
			"node_id":                  s.Config.NodeID,
			"uptime_s":                 int64(time.Since(s.startTime).Seconds()),
			"active_sessions":          activeKerberos,
			"active_kerberos_sessions": activeKerberos,
			"active_pty_sessions":      activePTY,
			"total_pty_frames":         atomic.LoadUint64(&s.ptyFrames),
			"total_rejected_frames":    0,
		})
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		defer s.state.mu.RUnlock()
		out := make([]map[string]any, 0, len(s.state.Sessions))
		for _, sess := range s.state.Sessions {
			sum := krb.Hash256(sess.KeyCV[:])
			out = append(out, map[string]any{
				"client_id":       sess.IDClient,
				"client_ip":       sess.ClientIP,
				"ad_c":            sess.ADc,
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
		writeJSONResponse(w, r, "[V]", "/api/sessions", map[string]any{"sessions": out})
	})
	mux.HandleFunc("/api/targets", func(w http.ResponseWriter, r *http.Request) {
		out := make([]map[string]any, 0, len(s.Config.SSHTargets))
		for _, target := range s.Config.SSHTargets {
			out = append(out, map[string]any{
				"id":              target.ID,
				"host":            target.Host,
				"port":            target.Port,
				"ssh_user":        target.SSHUser,
				"auth_type":       target.AuthType,
				"allowed_clients": target.AllowedClients,
			})
		}
		writeJSONResponse(w, r, "[V]", "/api/targets", map[string]any{"targets": out})
	})
	mux.HandleFunc("/api/auth_log", func(w http.ResponseWriter, r *http.Request) {
		limit := auditLimit(r.URL.Query().Get("limit"))
		records, err := s.audit.Records(limit, func(rec AuditRecord) bool {
			return rec.Kind == "auth"
		})
		if err != nil {
			writeJSONError(w, r, "[V]", "/api/auth_log", http.StatusInternalServerError, err)
			return
		}
		writeJSONResponse(w, r, "[V]", "/api/auth_log", map[string]any{"logs": records})
	})
	mux.HandleFunc("/api/pty_log", func(w http.ResponseWriter, r *http.Request) {
		limit := auditLimit(r.URL.Query().Get("limit"))
		records, err := s.audit.Records(limit, func(rec AuditRecord) bool {
			return rec.Kind == "pty"
		})
		if err != nil {
			writeJSONError(w, r, "[V]", "/api/pty_log", http.StatusInternalServerError, err)
			return
		}
		writeJSONResponse(w, r, "[V]", "/api/pty_log", map[string]any{"logs": records})
	})
	mux.HandleFunc("/api/audit/session/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/audit/session/")
		limit := auditLimit(r.URL.Query().Get("limit"))
		records, err := s.audit.Records(limit, auditSessionFilter(id))
		if err != nil {
			writeJSONError(w, r, "[V]", "/api/audit/session/:id", http.StatusInternalServerError, err)
			return
		}
		writeJSONResponse(w, r, "[V]", "/api/audit/session/:id", map[string]any{"session_id": id, "records": records})
	})
	mux.HandleFunc("/api/audit/replay/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/audit/replay/")
		limit := auditLimit(r.URL.Query().Get("limit"))
		records, err := s.audit.Records(limit, func(rec AuditRecord) bool {
			return rec.Kind == "pty" && rec.Direction == "V->C" && rec.FrameType == "output" && auditSessionFilter(id)(rec)
		})
		if err != nil {
			writeJSONError(w, r, "[V]", "/api/audit/replay/:id", http.StatusInternalServerError, err)
			return
		}
		// Records() returns newest first for log views. Replay needs chronological order.
		for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
			records[i], records[j] = records[j], records[i]
		}
		writeJSONResponse(w, r, "[V]", "/api/audit/replay/:id", map[string]any{"session_id": id, "frames": records})
	})
	mux.HandleFunc("/api/cert/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cert/")
		cert := s.clientCerts[id]
		if cert == nil {
			writeJSONError(w, r, "[V]", "/api/cert/:id", http.StatusNotFound, fmt.Errorf("certificate not found: %s", id))
			return
		}
		writeJSONResponse(w, r, "[V]", "/api/cert/:id", cert)
	})
	mux.HandleFunc("/api/verify_cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, r, "[V]", "/api/verify_cert", http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == "" {
			req.ID = r.URL.Query().Get("id")
		}
		cert := s.clientCerts[req.ID]
		if cert == nil {
			writeJSONError(w, r, "[V]", "/api/verify_cert", http.StatusNotFound, fmt.Errorf("certificate not found: %s", req.ID))
			return
		}
		if err := krb.CertVerify(cert); err != nil {
			writeJSONResponse(w, r, "[V]", "/api/verify_cert", map[string]any{"id": req.ID, "result": "fail", "reason": err.Error()})
			return
		}
		result := "ok"
		reason := ""
		if cert.ID != req.ID {
			result = "fail"
			reason = "certificate id mismatch"
		}
		writeJSONResponse(w, r, "[V]", "/api/verify_cert", map[string]any{"id": req.ID, "result": result, "reason": reason})
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Infof("[V] webui listening addr=%s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("[V] webui failed addr=%s err=%v", s.httpServer.Addr, err)
	}
}

func auditSessionFilter(id string) func(AuditRecord) bool {
	return func(rec AuditRecord) bool {
		if id == "" {
			return false
		}
		if rec.SessionID == id || rec.ClientID == id {
			return true
		}
		if rec.PTYSessionID > 0 && fmt.Sprintf("%d", rec.PTYSessionID) == id {
			return true
		}
		return false
	}
}

func writeJSONResponse(w http.ResponseWriter, r *http.Request, component string, route string, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Errorf("%s webui encode failed route=%s remote=%s err=%v", component, route, r.RemoteAddr, err)
		return
	}
	log.Infof("%s webui response sent route=%s remote=%s", component, route, r.RemoteAddr)
}

func writeJSONError(w http.ResponseWriter, r *http.Request, component string, route string, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
	log.Errorf("%s webui error route=%s remote=%s err=%v", component, route, r.RemoteAddr, err)
}
