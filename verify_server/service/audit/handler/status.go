package handler

import "github.com/gin-gonic/gin"

func (h *Handler) Status(c *gin.Context) {
	c.JSON(200, h.runtime.Status())
}

func (h *Handler) Sessions(c *gin.Context) {
	c.JSON(200, gin.H{"sessions": h.runtime.Sessions()})
}
