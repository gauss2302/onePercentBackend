// internal/middleware/logging.go
package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"runtime/debug"
)

// ErrorHandler middleware для продакшн обработки ошибок
func ErrorHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			log.Printf("Panic recovered: %s\n%s", err, debug.Stack())
		} else if err, ok := recovered.(error); ok {
			log.Printf("Panic recovered: %v\n%s", err, debug.Stack())
		} else {
			log.Printf("Panic recovered: %v\n%s", recovered, debug.Stack())
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
		})
	})
}

// RequestLogger логирует все запросы в продакшне
func RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] \"%s %s %s\" %d %s \"%s\" \"%s\" %s\n",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
			param.ClientIP,
		)
	})
}
