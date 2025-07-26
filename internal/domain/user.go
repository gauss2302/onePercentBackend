package domain

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID        uuid.UUID `json:"id" db:"id"`
	GoogleID  string    `json:"google_id" db:"google_id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	Picture   string    `json:"picture" db:"picture"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type GoogleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	TokenHash  string    `json:"-" db:"token_hash"` // Хэш токена, не отдаем в JSON
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	LastUsedAt time.Time `json:"last_used_at" db:"last_used_at"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	IsRevoked  bool      `json:"is_revoked" db:"is_revoked"`
}

type AuthResult struct {
	User   *User      `json:"user"`
	Tokens *TokenPair `json:"tokens"`
}
