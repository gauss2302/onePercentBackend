package router

import (
	"net/http"
	"onePercent/config"
	"onePercent/internal/handler"
	"onePercent/internal/middleware"
	"onePercent/internal/security"
	"time"

	"github.com/gin-gonic/gin"
)

type Router struct {
	authHandler    *handler.AuthHandler
	userHandler    *handler.UserHandler
	config         *config.Config
	rateLimiter    *security.RateLimiter
	csrfProtection *security.CSRFProtection
}

func NewRouter(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	config *config.Config,
	rateLimiter *security.RateLimiter,
	csrfProtection *security.CSRFProtection,
) *Router {
	return &Router{
		authHandler:    authHandler,
		userHandler:    userHandler,
		config:         config,
		rateLimiter:    rateLimiter,
		csrfProtection: csrfProtection,
	}
}

func (r *Router) SetupRoutes() *gin.Engine {
	if r.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware для продакшна и разработки
	if r.config.Environment == "production" {
		router.Use(middleware.RequestLogger())
		router.Use(middleware.ErrorHandler())
	} else {
		router.Use(gin.Logger())
		router.Use(gin.Recovery())
	}

	router.Use(middleware.CORS())
	router.Use(r.rateLimiter.GinMiddleware())

	api := router.Group("/api/v1")
	{
		// Health check endpoint (без защиты)
		api.GET("/health", r.healthCheck)

		// CSRF token endpoint
		api.GET("/csrf-token", r.csrfProtection.GinMiddleware(), r.getCSRFToken)

		api.GET("/test-core", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "auth group works"})
		})

		api.GET("/empty", r.emptyReq)

		// Auth routes
		r.setupAuthRoutes(api)

		// Protected routes
		r.setupProtectedRoutes(api)
	}

	return router
}

func (r *Router) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	})
}

func (r *Router) emptyReq(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":       "data Recieved",
		"timeStapm ": time.Now().Unix(),
	})
}

func (r *Router) getCSRFToken(c *gin.Context) {
	token := security.GetCSRFToken(c)
	c.JSON(http.StatusOK, gin.H{"csrf_token": token})
}

func (r *Router) setupAuthRoutes(api *gin.RouterGroup) {
	auth := api.Group("/auth")
	{
		// Тестовый роут для отладки
		auth.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "auth group works"})
		})

		// ================== WEB OAUTH FLOW ==================
		webAuth := auth.Group("/web")
		{
			webAuth.GET("/google", r.authHandler.GoogleAuth)
			webAuth.GET("/google/callback", r.csrfProtection.GinMiddleware(), r.authHandler.GoogleCallback)
			webAuth.POST("/exchange-code", r.csrfProtection.GinMiddleware(), r.authHandler.ExchangeAuthCode)
		}

		// ================== MOBILE OAUTH FLOW ==================
		mobileAuth := auth.Group("/mobile")
		{
			mobileAuth.POST("/google", r.csrfProtection.GinMiddleware(), r.authHandler.GoogleSignInMobile)
		}

		// Token management (требует CSRF защиты)
		auth.POST("/refresh", r.csrfProtection.GinMiddleware(), r.authHandler.RefreshToken)
		auth.POST("/logout", r.csrfProtection.GinMiddleware(), r.authHandler.Logout)

		// Refresh token management (требует аутентификации + CSRF)
		authProtected := auth.Group("/")
		authProtected.Use(middleware.AuthMiddleware(r.config.JWTSecret))
		{
			authProtected.GET("refresh-tokens", r.authHandler.GetRefreshTokens)
			authProtected.DELETE("refresh-tokens/revoke", r.csrfProtection.GinMiddleware(), r.authHandler.RevokeRefreshToken)
			authProtected.DELETE("refresh-tokens/revoke-all", r.csrfProtection.GinMiddleware(), r.authHandler.RevokeAllRefreshTokens)
		}
	}

}

func (r *Router) setupProtectedRoutes(api *gin.RouterGroup) {
	protected := api.Group("/")
	protected.Use(middleware.AuthMiddleware(r.config.JWTSecret))
	{
		// Profile endpoints (GET безопасен, PUT требует CSRF)
		protected.GET("profile", r.userHandler.GetProfile)
		protected.PUT("profile", r.csrfProtection.GinMiddleware(), r.userHandler.UpdateProfile)
	}
}
