package handler

import "github.com/gin-gonic/gin"

func (h *Handler) Certificate(c *gin.Context) {
	cert, err := h.runtime.Certificate(c.Param("id"))
	if err != nil {
		writeError(c, 404, err)
		return
	}
	c.JSON(200, cert)
}

func (h *Handler) VerifyCertificate(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.ID == "" {
		req.ID = c.Query("id")
	}
	result, status := h.runtime.VerifyCertificate(req.ID)
	c.JSON(status, result)
}
