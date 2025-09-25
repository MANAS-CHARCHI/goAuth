package middleware

import (
	"context"
	"goAuth/internal/database"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CHECK valid access token, is not expired, is not revoked from redis

func AuthMiddleware(m *database.UserModel) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.GetHeader("Authorization")
		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			return
		}

		tokenString := strings.TrimPrefix(accessToken, "Bearer ")
		jti, err := database.GetJtiFromToken(tokenString)
		if err != nil || jti == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		key := "user-jtis:" + jti
		val, err := m.Redis.Get(context.Background(), key).Result()
		if err == nil && val == "invalid" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
			return
		}
		c.Next()
	}
}
