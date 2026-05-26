package handler

import (
	"security-project/verify_server/config"

	"github.com/gin-gonic/gin"
)

func (h *Handler) Targets(c *gin.Context) {
	targets, err := h.audit.ListSSHTargets()
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"targets": targets})
}

func (h *Handler) SaveTarget(c *gin.Context) {
	var req struct {
		ID             string   `json:"id"`
		Host           string   `json:"host"`
		Port           int      `json:"port"`
		SSHUser        string   `json:"ssh_user"`
		AuthType       string   `json:"auth_type"`
		KeyPath        string   `json:"key_path"`
		Password       string   `json:"password"`
		KnownHostsPath string   `json:"known_hosts_path"`
		BlockedClients []string `json:"blocked_clients"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, 400, err)
		return
	}
	target := config.SSHTarget{
		ID:             req.ID,
		Host:           req.Host,
		Port:           req.Port,
		SSHUser:        req.SSHUser,
		AuthType:       req.AuthType,
		KeyPath:        req.KeyPath,
		Password:       req.Password,
		KnownHostsPath: req.KnownHostsPath,
		BlockedClients: req.BlockedClients,
	}
	if err := h.audit.UpsertSSHTarget(target); err != nil {
		writeError(c, 400, err)
		return
	}
	targets, err := h.audit.ListSSHTargets()
	if err != nil {
		writeError(c, 500, err)
		return
	}
	c.JSON(200, gin.H{"result": "ok", "targets": targets})
}

func (h *Handler) TargetPassword(c *gin.Context) {
	id := c.Param("id")
	password, err := h.audit.SSHTargetPassword(id)
	if err != nil {
		writeError(c, 404, err)
		return
	}
	c.JSON(200, gin.H{"id": id, "password": password})
}

func (h *Handler) UpdateTargetBlockedClients(c *gin.Context) {
	var req struct {
		BlockedClients []string `json:"blocked_clients"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, 400, err)
		return
	}
	blocked, err := h.audit.UpdateBlockedClients(c.Param("id"), req.BlockedClients)
	if err != nil {
		writeError(c, 400, err)
		return
	}
	c.JSON(200, gin.H{"result": "ok", "id": c.Param("id"), "blocked_clients": blocked})
}
