package gorush

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware simple Authorization token check
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqToken := c.GetHeader("Authorization")
		splitToken := strings.Split(reqToken, "Bearer")
		if PushConf.Auth.Enabled {
			if len(splitToken) != 2 {
				c.JSON(http.StatusForbidden, gin.H{"error": "invalid request, restricted endpoint"})
				c.Abort()
				return
			}
			apiKey := strings.TrimSpace(splitToken[1])
			if apiKey != PushConf.Auth.APIKEY {
				c.JSON(http.StatusForbidden, gin.H{"error": "invalid request, restricted endpoint"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
