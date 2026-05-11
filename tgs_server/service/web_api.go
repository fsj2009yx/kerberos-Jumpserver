package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"security-project/pkg/utils/log"
)

func (s *Service) runWebUI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, r, "[TGS]", "/api/status", map[string]any{
			"node_id":               s.Config.NodeID,
			"uptime_s":              int64(time.Since(s.startTime).Seconds()),
			"total_ticket_v_issued": atomic.LoadUint32(&s.ticketVIssued),
			"total_auth_fail":       0,
		})
	})
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		services := make([]map[string]any, 0, len(s.Config.ServiceDB))
		for _, item := range s.Config.ServiceDB {
			services = append(services, map[string]any{"id_v": item.IDV, "addr": item.Addr})
		}
		writeJSONResponse(w, r, "[TGS]", "/api/services", map[string]any{"services": services})
	})
	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(s.Config.WebUIHost, fmt.Sprintf("%d", s.Config.WebUIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Infof("[TGS] webui listening addr=%s", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("[TGS] webui failed addr=%s err=%v", s.httpServer.Addr, err)
	}
}

func writeJSONResponse(w http.ResponseWriter, r *http.Request, component string, route string, payload any) {
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Errorf("%s webui encode failed route=%s remote=%s err=%v", component, route, r.RemoteAddr, err)
		return
	}
	log.Infof("%s webui response sent route=%s remote=%s", component, route, r.RemoteAddr)
}
