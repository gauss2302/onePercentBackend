package handler

import (
	"context"
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

// ================== WEB OAUTH FLOW ==================

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	state := uuid.New().String()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)
	url := h.oauthService.GetAuthURL(state)
	c.JSON(http.StatusOK, gin.H{"auth_url": url})
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	// Проверка state
	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		h.redirectWithError(c, "invalid_state")
		return
	}

	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// Обмен кода на токен
	token, err := h.oauthService.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		h.redirectWithError(c, "exchange_failed")
		return
	}

	// Получение информации о пользователе
	userInfo, err := h.oauthService.GetUserInfo(c.Request.Context(), token)
	if err != nil {
		h.redirectWithError(c, "userinfo_failed")
		return
	}

	// Общая логика обработки пользователя
	user, err := h.processGoogleUser(c.Request.Context(), userInfo)
	if err != nil {
		h.redirectWithError(c, "user_processing_failed")
		return
	}

	// Генерируем токены
	tokenPair, err := h.generateUserTokens(c, user.ID)
	if err != nil {
		h.redirectWithError(c, "token_generation_failed")
		return
	}

	c.SetCookie(
		"refresh_token",
		tokenPair.RefreshToken,
		int(h.config.RefreshTokenTTL.Seconds()),
		"/",
		"",
		h.config.CookieSecure,
		true,
	)

	// Временное хранение для веб-клиента
	authCode := uuid.New().String()
	authResult := &domain.AuthResult{
		User: user,
		Tokens: &domain.TokenPair{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: "", // НЕ передаем refresh token на фронтенд
		},
	}

	if err := h.authService.StoreTemporaryAuth(authCode, authResult, 5*time.Minute); err != nil {
		h.redirectWithError(c, "storage_failed")
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

// ================== MOBILE OAUTH FLOW ==================

func (h *AuthHandler) GoogleSignInMobile(c *gin.Context) {
	var req struct {
		IDToken string `json:"id_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	userInfo, err := h.oauthService.VerifyIDToken(c.Request.Context(), req.IDToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Invalid Google ID token",
			"details": err.Error(),
		})
		return
	}

	user, err := h.processGoogleUser(c.Request.Context(), userInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "User processing failed",
			"details": err.Error(),
		})
		return
	}

	tokenPair, err := h.generateUserTokens(c, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Token generation failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":   user,
		"tokens": tokenPair,
	})

}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token found"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	tokenPair, err := h.authService.RefreshAccessToken(refreshTokenCookie, userAgent, ipAddress)
	if err != nil {
		// Чиста невалидного токена
		c.SetCookie("refresh_token", "", -1, "/", "", h.config.CookieSecure, true)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Новый токен в куку
	c.SetCookie(
		"refresh_token",
		tokenPair.RefreshToken,
		int(h.config.RefreshTokenTTL.Seconds()),
		"/",
		"",
		h.config.CookieSecure,
		true)

	c.JSON(http.StatusOK, gin.H{
		"tokens": gin.H{
			"access_token": tokenPair.AccessToken,
		},
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err == nil && refreshTokenCookie != "" {
		// Отзываем refresh token на сервере
		err := h.authService.RevokeRefreshToken(refreshTokenCookie)
		if err != nil {
			fmt.Sprintf("Error revoke refresh token: %s", err)
			return
		}
	}

	// Очищаем cookie
	c.SetCookie("refresh_token", "", -1, "/", "", h.config.CookieSecure, true)

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

func (h *AuthHandler) processGoogleUser(ctx context.Context, userInfo *domain.GoogleUserInfo) (*domain.User, error) {
	existingUser, err := h.userRepo.GetByGoogleID(ctx, userInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("database error when checking Google ID: %w", err)
	}

	if existingUser != nil {
		updated := false
		if existingUser.Name != userInfo.Name {
			existingUser.Name = userInfo.Name
			updated = true
		}
		if existingUser.Picture != userInfo.Picture {
			existingUser.Picture = userInfo.Picture
			updated = true
		}

		if updated {
			existingUser.UpdatedAt = time.Now()
			if err := h.userRepo.Update(ctx, existingUser); err != nil {
				return nil, fmt.Errorf("failed to update existing user: %w", err)
			}
		}
		return existingUser, nil
	}

	existingEmailUser, err := h.userRepo.GetByEmail(ctx, userInfo.Email)
	if err != nil {
		return nil, fmt.Errorf("database error when checking email: %w", err)
	}

	if existingEmailUser != nil {
		// Пользователь с таким email уже существует, но без Google ID
		// Связываем аккаунты
		existingEmailUser.GoogleID = userInfo.ID
		existingEmailUser.Name = userInfo.Name
		existingEmailUser.Picture = userInfo.Picture
		existingEmailUser.UpdatedAt = time.Now()

		if err := h.userRepo.Update(ctx, existingEmailUser); err != nil {
			return nil, fmt.Errorf("failed to link Google account: %w", err)
		}

		return existingEmailUser, nil
	}

	user := &domain.User{
		ID:        uuid.New(),
		GoogleID:  userInfo.ID,
		Email:     userInfo.Email,
		Name:      userInfo.Name,
		Picture:   userInfo.Picture,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := h.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create new user: %w", err)
	}

	return user, nil

}

func (h *AuthHandler) redirectWithError(c *gin.Context, errorType string) {
	frontendURL := fmt.Sprintf("%s/auth/login?error=%s", h.config.FrontendURL, errorType)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func (h *AuthHandler) generateUserTokens(c *gin.Context, userID uuid.UUID) (*domain.TokenPair, error) {
	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	return h.authService.GenerateTokenPair(userID, userAgent, ipAddress)
}
