package router

import (
	"security-project/verify_server/service/audit/handler"
	"security-project/verify_server/service/audit/middleware"
	auditservices "security-project/verify_server/service/audit/services"

	"github.com/gin-gonic/gin"
)

func New(audit *auditservices.Manager, runtime handler.Runtime) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(middleware.AccessLog("[V]"))

	h := handler.New(audit, runtime)
	api := engine.Group("/api")
	api.GET("/status", h.Status)
	api.GET("/sessions", h.Sessions)
	api.GET("/targets", h.Targets)
	api.POST("/targets", h.SaveTarget)
	api.GET("/targets/:id/password", h.TargetPassword)
	api.PUT("/targets/:id/blocked_clients", h.UpdateTargetBlockedClients)
	api.GET("/auth_log", h.AuthLog)
	api.GET("/pty_log", h.PTYLog)
	api.GET("/audit/frames", h.AuditFrames)
	api.GET("/audit/replay", h.AuditReplay)
	api.GET("/cert/:id", h.Certificate)
	api.POST("/verify_cert", h.VerifyCertificate)

	return engine
}
