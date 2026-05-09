package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		active := len(s.state.Sessions)
		s.state.mu.RUnlock()
		writeJSONResponse(w, r, "[V]", "/api/status", map[string]any{
			"node_id":               s.Config.NodeID,
			"uptime_s":              int64(time.Since(s.startTime).Seconds()),
			"active_sessions":       active,
			"total_pty_frames":      atomic.LoadUint64(&s.ptyFrames),
			"total_rejected_frames": 0,
		})
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		s.state.mu.RLock()
		defer s.state.mu.RUnlock()
		out := make([]map[string]any, 0, len(s.state.Sessions))
		for _, sess := range s.state.Sessions {
			sum := krb.Hash256(sess.KeyCV[:])
			out = append(out, map[string]any{
				"client_id":      sess.IDClient,
				"client_ip":      sess.ADc,
				"k_cv_sha256":    hex.EncodeToString(sum[:8]),
				"expire_at":      sess.ExpireAt,
				"last_io_ts":     sess.LastIO.Unix(),
				"total_frames":   sess.TotalFrames,
				"pty_session_id": sess.PtySessionID,
			})
		}
		writeJSONResponse(w, r, "[V]", "/api/sessions", map[string]any{"sessions": out})
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

func writeJSONResponse(w http.ResponseWriter, r *http.Request, component string, route string, payload any) {
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Errorf("%s webui encode failed route=%s remote=%s err=%v", component, route, r.RemoteAddr, err)
		return
	}
	log.Infof("%s webui response sent route=%s remote=%s", component, route, r.RemoteAddr)
}
