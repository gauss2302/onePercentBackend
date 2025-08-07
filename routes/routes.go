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
	skillHandler   *handler.SkillHandler
	config         *config.Config
	rateLimiter    *security.RateLimiter
	csrfProtection *security.CSRFProtection
}

func NewRouter(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	skillHandler *handler.SkillHandler,
	config *config.Config,
	rateLimiter *security.RateLimiter,
	csrfProtection *security.CSRFProtection,
) *Router {
	return &Router{
		authHandler:    authHandler,
		userHandler:    userHandler,
		skillHandler:   skillHandler,
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
		api.GET("/health", r.healthCheck)

		api.GET("/csrf-token", r.csrfProtection.GinMiddleware(), r.getCSRFToken)

		r.setupAuthRoutes(api)

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

func (r *Router) getCSRFToken(c *gin.Context) {
	token := security.GetCSRFToken(c)
	c.JSON(http.StatusOK, gin.H{"csrf_token": token})
}

func (r *Router) setupAuthRoutes(api *gin.RouterGroup) {
	auth := api.Group("/auth")
	{
		// Web OAuth flow
		webAuth := auth.Group("/web")
		{
			// GET requests don't need CSRF
			webAuth.GET("/google", r.authHandler.GoogleAuth)
			webAuth.GET("/google/callback", r.authHandler.GoogleCallback)

			// POST request needs CSRF
			webAuth.POST("/exchange-code", r.csrfProtection.GinMiddleware(), r.authHandler.ExchangeAuthCode)
		}

		// Mobile OAuth flow
		mobileAuth := auth.Group("/mobile")
		{
			// Mobile endpoints might not have CSRF tokens initially
			mobileAuth.POST("/google", r.authHandler.GoogleSignInMobile)
		}

		// Token management
		// IMPORTANT: Refresh endpoint skips CSRF validation but generates new token
		// The refresh token cookie itself provides security
		auth.POST("/refresh", r.csrfProtection.SkipCSRFForRefresh(), r.authHandler.RefreshToken)

		// Logout requires CSRF
		auth.POST("/logout", r.csrfProtection.GinMiddleware(), r.authHandler.Logout)

		// Refresh token management (requires authentication + CSRF)
		authProtected := auth.Group("/")
		authProtected.Use(middleware.AuthMiddleware(r.config.JWTSecret))
		{
			authProtected.GET("/refresh-tokens", r.authHandler.GetRefreshTokens)
			authProtected.DELETE("/refresh-tokens/revoke", r.csrfProtection.GinMiddleware(), r.authHandler.RevokeRefreshToken)
			authProtected.DELETE("/refresh-tokens/revoke-all", r.csrfProtection.GinMiddleware(), r.authHandler.RevokeAllRefreshTokens)
		}
	}
}

func (r *Router) setupProtectedRoutes(api *gin.RouterGroup) {
	protected := api.Group("/")
	protected.Use(middleware.AuthMiddleware(r.config.JWTSecret))
	{
		// Profile endpoints (GET is safe, PUT requires CSRF)
		protected.GET("/profile", r.userHandler.GetProfile)
		protected.PUT("/profile", r.csrfProtection.GinMiddleware(), r.userHandler.UpdateProfile)
	}

	// Skills endpoints
	skills := api.Group("/skills")
	skills.Use(middleware.AuthMiddleware(r.config.JWTSecret))
	{
		skills.POST("/", r.csrfProtection.GinMiddleware(), r.skillHandler.CreateSkill)
		skills.GET("/", r.skillHandler.GetUserSkills)
		skills.GET("/category/:category", r.skillHandler.GetUserSkillsByCategory)
		skills.PUT("/:skillID", r.csrfProtection.GinMiddleware(), r.skillHandler.UpdateSkill)
		skills.DELETE("/:skillID", r.csrfProtection.GinMiddleware(), r.skillHandler.DeleteSkill)
		skills.DELETE("/", r.csrfProtection.GinMiddleware(), r.skillHandler.DeleteAllUserSkills)
	}
}

// conditionalCSRF applies CSRF protection but doesn't fail if token is missing
// This is useful for refresh endpoint where the user might come back after CSRF expired
func (r *Router) conditionalCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to validate CSRF token if present
		csrfToken := c.GetHeader("X-CSRF-Token")

		if csrfToken != "" {
			// Validate the token if provided
			r.csrfProtection.GinMiddleware()(c)

			// If validation failed, the middleware will abort
			if c.IsAborted() {
				return
			}
		} else {
			// No CSRF token provided - for refresh endpoint, we'll allow it
			// The refresh token itself is the security mechanism
			// BUT we should set a new CSRF token for future requests
			token, err := r.csrfProtection.GenerateToken()
			if err == nil {
				c.Set("csrf_token", token)

				// Set the cookie for future requests
				c.SetCookie(
					"csrf_token",
					token,
					86400, // 24 hours
					"/",
					"",
					r.config.CookieSecure,
					true, // HttpOnly
				)
			}
		}

		c.Next()
	}
}
