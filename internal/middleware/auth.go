package middleware

import (
	"fmt"
	"net/http"
	"onePercent/internal/service"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// First, try to get token from cookie (web clients)
		if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
			tokenString = cookie
		} else {
			// Fallback to Authorization header (mobile clients)
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				if tokenString == authHeader {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
					c.Abort()
					return
				}
			}
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Parse JWT token
		token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			// Clear invalid cookie if it exists
			c.SetCookie("access_token", "", -1, "/", "", false, true)

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*service.Claims); ok && token.Valid {
			c.Set("user_id", claims.UserID)
			c.Set("token_id", claims.TokenID)
			c.Next()
		} else {
			// Clear invalid cookie if it exists
			c.SetCookie("access_token", "", -1, "/", "", false, true)

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}
	}
}

// Optional: Middleware for routes that can work with or without auth
func OptionalAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// Try to get token from cookie first
		if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
			tokenString = cookie
		} else {
			// Fallback to Authorization header
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// If no token, continue without auth
		if tokenString == "" {
			c.Set("user_id", nil)
			c.Set("is_authenticated", false)
			c.Next()
			return
		}

		// Try to parse token
		token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err == nil && token.Valid {
			if claims, ok := token.Claims.(*service.Claims); ok {
				c.Set("user_id", claims.UserID)
				c.Set("token_id", claims.TokenID)
				c.Set("is_authenticated", true)
			}
		} else {
			c.Set("user_id", nil)
			c.Set("is_authenticated", false)
		}

		c.Next()
	}
}
