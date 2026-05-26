package handler

import (
	"strconv"

	"security-project/verify_server/service/audit/model"
	auditservices "security-project/verify_server/service/audit/services"

	"github.com/gin-gonic/gin"
)

type Runtime interface {
	Status() map[string]any
	Sessions() []map[string]any
	Certificate(id string) (any, error)
	VerifyCertificate(id string) (map[string]any, int)
}

type Handler struct {
	audit   *auditservices.Manager
	runtime Runtime
}

func New(audit *auditservices.Manager, runtime Runtime) *Handler {
	return &Handler{audit: audit, runtime: runtime}
}

func auditLimit(raw string) int {
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func auditSessionFilter(id string) func(model.Record) bool {
	return func(rec model.Record) bool {
		if id == "" {
			return false
		}
		if rec.SessionID == id || rec.ClientID == id {
			return true
		}
		if rec.PTYSessionID > 0 && strconv.FormatUint(uint64(rec.PTYSessionID), 10) == id {
			return true
		}
		return false
	}
}

func writeError(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"error": err.Error()})
}

func methodNotAllowed(c *gin.Context) {
	c.JSON(405, gin.H{"error": "method not allowed"})
}
