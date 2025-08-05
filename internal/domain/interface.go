package domain

import (
	"context"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"time"
)

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByGoogleID(ctx context.Context, googleID string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error)
	Update(ctx context.Context, token *RefreshToken) error
	Delete(ctx context.Context, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
	StoreTemporaryAuth(ctx context.Context, authCode, authData string, expiration time.Duration) error
	GetTemporaryAuth(ctx context.Context, authCode string) (string, error)
	VerifyTokenOwnership(background context.Context, hash string, id uuid.UUID) (bool, error)
}

type OAuthService interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error)

	// Mobile OAuth flow
	VerifyIDToken(ctx context.Context, idToken string) (*GoogleUserInfo, error)
}

type AuthService interface {
	GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (uuid.UUID, error)
	RefreshAccessToken(refreshToken string, userAgent, ipAddress string) (*TokenPair, error)
	RevokeRefreshToken(refreshToken string) error
	GetUserRefreshTokens(userID uuid.UUID) ([]*RefreshToken, error)
	RevokeAllUserRefreshTokens(userID uuid.UUID) error
	StoreTemporaryAuth(authCode string, authResult *AuthResult, expiration time.Duration) error
	ExchangeAuthCode(authCode string) (*AuthResult, error)
	CleanupExpiredTokens() error
	VerifyRefreshTokenOwnership(refreshTokenStr string, userID uuid.UUID) (bool, error)
}
