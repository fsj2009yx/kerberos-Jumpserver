package middleware

import (
	"time"

	"security-project/pkg/utils/log"

	"github.com/gin-gonic/gin"
)

func AccessLog(component string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Infof("%s webui request method=%s path=%s status=%d remote=%s cost_ms=%d",
			component, c.Request.Method, c.Request.URL.Path, c.Writer.Status(), c.ClientIP(), time.Since(start).Milliseconds())
	}
}
