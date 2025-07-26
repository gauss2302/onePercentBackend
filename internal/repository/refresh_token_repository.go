// internal/repository/refresh_token_repository.go
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"onePercent/internal/domain"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type refreshTokenRepository struct {
	client *redis.Client
}

func NewRefreshTokenRepository(client *redis.Client) domain.RefreshTokenRepository {
	return &refreshTokenRepository{client: client}
}

func (r *refreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	tokenKey := fmt.Sprintf("refresh_token:%s", token.TokenHash)
	userTokensKey := fmt.Sprintf("user_refresh_tokens:%s", token.UserID.String())

	pipe := r.client.Pipeline()

	tokenData, err := json.Marshal(token)
	if err != nil {
		return err
	}

	// Сохраняем сам токен
	pipe.Set(ctx, tokenKey, tokenData, time.Until(token.ExpiresAt))

	// Добавляем токен в список пользователя
	pipe.SAdd(ctx, userTokensKey, token.TokenHash)
	pipe.Expire(ctx, userTokensKey, 30*24*time.Hour) // 30 дней

	_, err = pipe.Exec(ctx)
	return err
}

func (r *refreshTokenRepository) GetByToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	tokenKey := fmt.Sprintf("refresh_token:%s", tokenHash)

	data, err := r.client.Get(ctx, tokenKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var token domain.RefreshToken
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *refreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error) {
	userTokensKey := fmt.Sprintf("user_refresh_tokens:%s", userID.String())

	tokenHashes, err := r.client.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return nil, err
	}

	var tokens []*domain.RefreshToken
	for _, tokenHash := range tokenHashes {
		token, err := r.GetByToken(ctx, tokenHash)
		if err != nil {
			continue // Пропускаем невалидные токены
		}
		if token != nil && !token.IsRevoked {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

func (r *refreshTokenRepository) Update(ctx context.Context, token *domain.RefreshToken) error {
	tokenKey := fmt.Sprintf("refresh_token:%s", token.TokenHash)

	tokenData, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, tokenKey, tokenData, time.Until(token.ExpiresAt)).Err()
}

func (r *refreshTokenRepository) Delete(ctx context.Context, tokenHash string) error {
	tokenKey := fmt.Sprintf("refresh_token:%s", tokenHash)

	// Получаем токен чтобы узнать userID
	token, err := r.GetByToken(ctx, tokenHash)
	if err != nil || token == nil {
		return err
	}

	userTokensKey := fmt.Sprintf("user_refresh_tokens:%s", token.UserID.String())

	pipe := r.client.Pipeline()
	pipe.Del(ctx, tokenKey)
	pipe.SRem(ctx, userTokensKey, tokenHash)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *refreshTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	tokens, err := r.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if len(tokens) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	userTokensKey := fmt.Sprintf("user_refresh_tokens:%s", userID.String())

	for _, token := range tokens {
		tokenKey := fmt.Sprintf("refresh_token:%s", token.TokenHash)
		pipe.Del(ctx, tokenKey)
	}

	pipe.Del(ctx, userTokensKey)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	// В Redis токены автоматически удаляются по TTL
	// Но мы можем дополнительно почистить пользовательские списки от несуществующих токенов

	// Получаем все ключи пользователей
	pattern := "user_refresh_tokens:*"
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	for _, userKey := range keys {
		// Получаем все токены пользователя
		tokenHashes, err := r.client.SMembers(ctx, userKey).Result()
		if err != nil {
			continue
		}

		// Проверяем каждый токен и удаляем из множества если он больше не существует
		for _, tokenHash := range tokenHashes {
			tokenKey := fmt.Sprintf("refresh_token:%s", tokenHash)
			exists, err := r.client.Exists(ctx, tokenKey).Result()
			if err != nil {
				continue
			}

			if exists == 0 {
				// Токен не существует, удаляем из множества пользователя
				r.client.SRem(ctx, userKey, tokenHash)
			}
		}
	}

	return nil
}

func (r *refreshTokenRepository) VerifyTokenOwnership(ctx context.Context, tokenHash string, userID uuid.UUID) (bool, error) {
	token, err := r.GetByToken(ctx, tokenHash)
	if err != nil {
		return false, err
	}

	if token == nil {
		return false, nil
	}

	return token.UserID == userID && !token.IsRevoked, nil
}

func (r *refreshTokenRepository) StoreTemporaryAuth(ctx context.Context, authCode, authData string, expiration time.Duration) error {
	key := fmt.Sprintf("temp_auth:%s", authCode)
	return r.client.Set(ctx, key, authData, expiration).Err()
}

func (r *refreshTokenRepository) GetTemporaryAuth(ctx context.Context, authCode string) (string, error) {
	key := fmt.Sprintf("temp_auth:%s", authCode)
	result, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	// Удаляем после получения (одноразовое использование)
	r.client.Del(ctx, key)

	return result, nil
}
