package handler

import (
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
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "pty"
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"logs": records})
}

func (h *Handler) AuditSession(c *gin.Context) {
	id := c.Param("id")
	records, err := h.audit.Records(auditLimit(c.Query("limit")), auditSessionFilter(id))
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"session_id": id, "records": records})
}

func (h *Handler) AuditReplay(c *gin.Context) {
	id := c.Param("id")
	filter := auditSessionFilter(id)
	records, err := h.audit.Records(auditLimit(c.Query("limit")), func(rec model.Record) bool {
		return rec.Kind == "pty" && rec.Direction == "V->C" && rec.FrameType == "output" && filter(rec)
	})
	if err != nil {
		writeError(c, 500, err)
		return
	}
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	c.JSON(200, gin.H{"session_id": id, "frames": records})
}
