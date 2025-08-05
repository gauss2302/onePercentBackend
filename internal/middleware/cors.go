package middleware

import (
	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow specific origins (add your frontend URLs)
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"https://localhost:3000",
			"*", // ← Исправлено: * вместо **
		}

		// Check if origin is allowed
		var allowOrigin string
		for _, allowedOrigin := range allowedOrigins { // ← Исправлено: _, вместо *,
			if origin == allowedOrigin || allowedOrigin == "*" {
				if allowedOrigin == "*" {
					allowOrigin = "*" // Разрешить всем
				} else {
					allowOrigin = origin
				}
				break
			}
		}

		// Если origin не найден, но есть *, то разрешаем всем
		if allowOrigin == "" {
			for _, allowed := range allowedOrigins {
				if allowed == "*" {
					allowOrigin = "*"
					break
				}
			}
		}

		// Fallback для разработки
		if allowOrigin == "" {
			allowOrigin = "http://localhost:3000" // Default for development
		}

		c.Header("Access-Control-Allow-Origin", allowOrigin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func CORSWithConfig(allowedOrigins []string, allowCredentials bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Validate against whitelist
		var allowOrigin string
		for _, allowed := range allowedOrigins { // ← Исправлено: _, вместо *,
			if origin == allowed || allowed == "*" {
				if allowed == "*" {
					allowOrigin = "*"
				} else {
					allowOrigin = origin
				}
				break
			}
		}

		// For development, allow localhost variants if not in production
		if allowOrigin == "" && len(allowedOrigins) == 0 {
			// Development fallback
			if origin == "http://localhost:3000" || origin == "http://127.0.0.1:3000" {
				allowOrigin = origin
			}
		}

		if allowOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowOrigin)
		}

		if allowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
