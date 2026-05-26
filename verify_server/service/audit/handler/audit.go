package handler

import (
	"strings"

	"security-project/verify_server/service/audit/model"

	"github.com/gin-gonic/gin"
)

func (h *Handler) AuthLog(c *gin.Context) {
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "auth"
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"logs": records})
}

func (h *Handler) PTYLog(c *gin.Context) {
	hasTargetFilter := strings.TrimSpace(c.Query("client_id")) != "" || strings.TrimSpace(c.Query("target_id")) != ""
	targetFilter := auditTargetFilter(c.Query("client_id"), c.Query("target_id"))
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "pty" && (!hasTargetFilter || targetFilter(rec))
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"logs": records})
}

func (h *Handler) AuditFrames(c *gin.Context) {
	targetFilter := auditTargetFilter(c.Query("client_id"), c.Query("target_id"))
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "pty" && targetFilter(rec)
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{
		"client_id": c.Query("client_id"),
		"target_id": c.Query("target_id"),
		"records":   records,
	})
}

func (h *Handler) AuditReplay(c *gin.Context) {
	filter := auditTargetFilter(c.Query("client_id"), c.Query("target_id"))
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "pty" && filter(rec)
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	c.JSON(200, gin.H{
		"client_id": c.Query("client_id"),
		"target_id": c.Query("target_id"),
		"frames":    records,
	})
}
