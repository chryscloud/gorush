package gorush

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware simple Authorization token check
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		currentPath := c.Request.URL.Path
		if !strings.Contains(currentPath, "health") {
			reqToken := c.GetHeader("Authorization")
			splitToken := strings.Split(reqToken, "APIKEY")
			if PushConf.Auth.Enabled {
				if len(splitToken) != 2 {
					c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
					c.Abort()
					return
				}
				apiKey := strings.TrimSpace(splitToken[1])
				if apiKey != PushConf.Auth.APIKEY {
					c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
					c.Abort()
					return
				}
			}
		}
		c.Next()
	}
}
