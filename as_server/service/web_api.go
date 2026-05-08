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

	"github.com/fatedier/golib/log"

	"security-project/common/krb"
)

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"node_id":          s.Config.NodeID,
			"uptime_s":         int64(time.Since(s.startTime).Seconds()),
			"total_tgt_issued": atomic.LoadUint32(&s.nextSeq),
			"total_auth_fail":  0,
			"thread_pool_size": s.Config.ThreadPoolSize,
			"thread_pool_busy": 0,
			"client_count":     len(s.state.Clients),
		}
		writeJSONResponse(w, r, "[AS]", "/api/status", resp)
	})
	mux.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			ID      string `json:"id"`
			CertID  string `json:"cert_id"`
			CertExp string `json:"cert_expire"`
		}
		out := make([]item, 0, len(s.Config.ClientDB))
		for _, c := range s.Config.ClientDB {
			out = append(out, item{ID: c.ID, CertID: c.CertPath, CertExp: ""})
		}
		writeJSONResponse(w, r, "[AS]", "/api/clients", map[string]any{"clients": out})
	})
	mux.HandleFunc("/api/keys_summary", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			ClientID  string `json:"client_id"`
			KCTGSHash string `json:"k_ctgs_sha256"`
			IssuedAt  uint32 `json:"issued_at"`
			ExpireAt  uint32 `json:"expire_at"`
		}
		out := make([]item, 0, len(s.state.Clients))
		for id, secret := range s.state.Clients {
			sum := krb.Hash256(secret.Kc[:])
			out = append(out, item{
				ClientID:  id,
				KCTGSHash: hex.EncodeToString(sum[:8]),
				IssuedAt:  uint32(time.Now().Unix()),
				ExpireAt:  uint32(time.Now().Add(time.Duration(s.Config.TicketLifetimeSec) * time.Second).Unix()),
			})
		}
		writeJSONResponse(w, r, "[AS]", "/api/keys_summary", map[string]any{"keys": out})
	})
	mux.HandleFunc("/api/cert/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cert/")
		for _, c := range s.Config.ClientDB {
			if c.ID != id {
				continue
			}
			if c.CertPath == "" {
				log.Warnf("[AS] webui cert not found remote=%s client=%s reason=empty_path", r.RemoteAddr, id)
				http.NotFound(w, r)
				return
			}
			cert, err := krb.CertLoad(c.CertPath)
			if err != nil {
				log.Warnf("[AS] webui cert load failed remote=%s client=%s path=%s err=%v", r.RemoteAddr, id, c.CertPath, err)
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSONResponse(w, r, "[AS]", "/api/cert/", cert)
			return
		}
		log.Warnf("[AS] webui cert not found remote=%s client=%s", r.RemoteAddr, id)
		http.NotFound(w, r)
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Infof("[AS] webui listening addr=%s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("[AS] webui failed addr=%s err=%v", s.httpServer.Addr, err)
	}
}

func writeJSONResponse(w http.ResponseWriter, r *http.Request, component string, route string, payload any) {
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Errorf("%s webui response encode failed route=%s remote=%s err=%v", component, route, r.RemoteAddr, err)
		return
	}
	log.Infof("%s webui response sent route=%s remote=%s", component, route, r.RemoteAddr)
}
