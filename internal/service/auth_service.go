package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"onePercent/config"
	"onePercent/internal/domain"
	"time"
)

type authService struct {
	jwtSecret        string
	userRepo         domain.UserRepository
	refreshTokenRepo domain.RefreshTokenRepository
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
}

type Claims struct {
	UserID  uuid.UUID `json:"user_id"`
	TokenID string    `json:"token_id"` // Уникальный ID для этого токена
	jwt.RegisteredClaims
}

func NewAuthService(cfg *config.Config, userRepo domain.UserRepository, refreshTokenRepo domain.RefreshTokenRepository) domain.AuthService {
	return &authService{
		jwtSecret:        cfg.JWTSecret,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		accessTokenTTL:   15 * time.Minute,    // 15 минут для access token
		refreshTokenTTL:  30 * 24 * time.Hour, // 30 дней для refresh token
	}
}

func (s *authService) StoreTemporaryAuth(authCode string, authResult *domain.AuthResult, expiration time.Duration) error {
	authResultJSON, err := json.Marshal(authResult)
	if err != nil {
		return err
	}

	return s.refreshTokenRepo.StoreTemporaryAuth(context.Background(), authCode, string(authResultJSON), expiration)
}

func (s *authService) ExchangeAuthCode(authCode string) (*domain.AuthResult, error) {
	authData, err := s.refreshTokenRepo.GetTemporaryAuth(context.Background(), authCode)
	if err != nil {
		return nil, err
	}

	if authData == "" {
		return nil, fmt.Errorf("invalid or expired auth code")
	}

	var authResult domain.AuthResult
	if err := json.Unmarshal([]byte(authData), &authResult); err != nil {
		return nil, err
	}

	return &authResult, nil
}

func (s *authService) GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*domain.TokenPair, error) {
	// Генерируем уникальный ID для токена
	tokenID := uuid.New().String()

	// Генерируем access token
	accessToken, err := s.generateAccessToken(userID, tokenID)
	if err != nil {
		return nil, err
	}

	// Генерируем refresh token
	refreshTokenStr, refreshTokenHash, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Создаем запись refresh token
	refreshToken := &domain.RefreshToken{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  refreshTokenHash,
		ExpiresAt:  time.Now().Add(s.refreshTokenTTL),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		IsRevoked:  false,
	}

	if err := s.refreshTokenRepo.Create(context.Background(), refreshToken); err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenStr,
	}, nil
}

func (s *authService) generateAccessToken(userID uuid.UUID, tokenID string) (string, error) {
	claims := &Claims{
		UserID:  userID,
		TokenID: tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authService) generateRefreshToken() (token, hash string, err error) {
	// Генерируем случайные байты для токена
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}

	token = hex.EncodeToString(tokenBytes)

	// Создаем хэш токена для хранения
	hasher := sha256.New()
	hasher.Write([]byte(token))
	hash = hex.EncodeToString(hasher.Sum(nil))

	return token, hash, nil
}

func (s *authService) ValidateAccessToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Проверяем, что пользователь существует
		user, err := s.userRepo.GetByID(context.Background(), claims.UserID)
		if err != nil || user == nil {
			return uuid.Nil, fmt.Errorf("user not found")
		}

		return claims.UserID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid token")
}

func (s *authService) RefreshAccessToken(refreshTokenStr string, userAgent, ipAddress string) (*domain.TokenPair, error) {
	// Хэшируем полученный токен
	hasher := sha256.New()
	hasher.Write([]byte(refreshTokenStr))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	// Ищем токен в базе
	refreshToken, err := s.refreshTokenRepo.GetByToken(context.Background(), tokenHash)
	if err != nil || refreshToken == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Проверяем срок действия
	if time.Now().After(refreshToken.ExpiresAt) {
		// Удаляем истекший токен
		s.refreshTokenRepo.Delete(context.Background(), tokenHash)
		return nil, fmt.Errorf("refresh token expired")
	}

	// Проверяем, что токен не отозван
	if refreshToken.IsRevoked {
		return nil, fmt.Errorf("refresh token is revoked")
	}

	// Обновляем время последнего использования
	refreshToken.LastUsedAt = time.Now()
	s.refreshTokenRepo.Update(context.Background(), refreshToken)

	// РОТАЦИЯ: Удаляем старый refresh token
	s.refreshTokenRepo.Delete(context.Background(), tokenHash)

	// Генерируем новую пару токенов
	return s.GenerateTokenPair(refreshToken.UserID, userAgent, ipAddress)
}

func (s *authService) RevokeRefreshToken(refreshTokenStr string) error {
	// Хэшируем токен
	hasher := sha256.New()
	hasher.Write([]byte(refreshTokenStr))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	return s.refreshTokenRepo.Delete(context.Background(), tokenHash)
}

func (s *authService) GetUserRefreshTokens(userID uuid.UUID) ([]*domain.RefreshToken, error) {
	return s.refreshTokenRepo.GetByUserID(context.Background(), userID)
}

func (s *authService) RevokeAllUserRefreshTokens(userID uuid.UUID) error {
	return s.refreshTokenRepo.DeleteByUserID(context.Background(), userID)
}

func (s *authService) VerifyRefreshTokenOwnership(refreshTokenStr string, userID uuid.UUID) (bool, error) {
	// Хэшируем токен
	hasher := sha256.New()
	hasher.Write([]byte(refreshTokenStr))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	return s.refreshTokenRepo.VerifyTokenOwnership(context.Background(), tokenHash, userID)
}

func (s *authService) CleanupExpiredTokens() error {
	return s.refreshTokenRepo.DeleteExpired(context.Background())
}
