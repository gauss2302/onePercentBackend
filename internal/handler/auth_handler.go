package handler

import (
	"fmt"
	"onePercent/config"
	"onePercent/internal/domain"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	oauthService domain.OAuthService
	authService  domain.AuthService
	userRepo     domain.UserRepository
	config       *config.Config
}

func NewAuthHandler(oauthService domain.OAuthService, authService domain.AuthService, userRepo domain.UserRepository, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		oauthService: oauthService,
		authService:  authService,
		userRepo:     userRepo,
		config:       cfg,
	}
}

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	state := uuid.New().String()

	c.SetCookie("oauth_state", state, 600, "/", "", false, true)

	url := h.oauthService.GetAuthURL(state)
	c.JSON(http.StatusOK, gin.H{"auth_url": url})
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		frontendURL := fmt.Sprintf("%s/auth/login?error=invalid_state", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	token, err := h.oauthService.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=exchange_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	userInfo, err := h.oauthService.GetUserInfo(c.Request.Context(), token)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=userinfo_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	// Проверяем, существует ли пользователь
	existingUser, err := h.userRepo.GetByGoogleID(c.Request.Context(), userInfo.ID)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=database_error", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	var user *domain.User
	if existingUser == nil {
		// Создаем нового пользователя
		user = &domain.User{
			ID:        uuid.New(),
			GoogleID:  userInfo.ID,
			Email:     userInfo.Email,
			Name:      userInfo.Name,
			Picture:   userInfo.Picture,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := h.userRepo.Create(c.Request.Context(), user); err != nil {
			frontendURL := fmt.Sprintf("%s/auth/login?error=user_creation_failed", h.config.FrontendURL)
			c.Redirect(http.StatusTemporaryRedirect, frontendURL)
			return
		}
	} else {
		user = existingUser
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	// Генерируем пару токенов
	tokenPair, err := h.authService.GenerateTokenPair(user.ID, userAgent, ipAddress)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=token_generation_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	// Генерируем код для временного хранения результата аутентификации
	authCode := uuid.New().String()
	authResult := &domain.AuthResult{
		User:   user,
		Tokens: tokenPair,
	}

	if err := h.authService.StoreTemporaryAuth(authCode, authResult, 5*time.Minute); err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=storage_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	frontendURL := fmt.Sprintf("%s/auth/callback?auth_code=%s", h.config.FrontendURL, authCode)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func (h *AuthHandler) ExchangeAuthCode(c *gin.Context) {
	var req struct {
		AuthCode string `json:"auth_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	authResult, err := h.authService.ExchangeAuthCode(req.AuthCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired auth code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":   authResult.User,
		"tokens": authResult.Tokens,
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	tokenPair, err := h.authService.RefreshAccessToken(req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokenPair})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.RevokeRefreshToken(req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *AuthHandler) GetRefreshTokens(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	refreshTokens, err := h.authService.GetUserRefreshTokens(userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get refresh tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refresh_tokens": refreshTokens})
}

func (h *AuthHandler) RevokeRefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Проверяем, что токен принадлежит пользователю
	isOwner, err := h.authService.VerifyRefreshTokenOwnership(req.RefreshToken, userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify token ownership"})
		return
	}

	if !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "Token not found or unauthorized"})
		return
	}

	if err := h.authService.RevokeRefreshToken(req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

func (h *AuthHandler) RevokeAllRefreshTokens(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	if err := h.authService.RevokeAllUserRefreshTokens(userID.(uuid.UUID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke all tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All tokens revoked successfully"})
}
