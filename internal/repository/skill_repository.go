package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"onePercent/internal/domain"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type skillRepository struct {
	db *sql.DB
}

func NewSkillRepository(db *sql.DB) domain.SkillRepository {
	return &skillRepository{
		db: db,
	}
}

func (r *skillRepository) Create(ctx context.Context, skill *domain.Skill) error {
	query := `
		INSERT INTO skills (user_id, name, category, proficiency)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query,
		skill.UserID,
		skill.Name,
		skill.Category,
		skill.Proficiency,
	).Scan(&skill.ID, &skill.CreatedAt, &skill.UpdatedAt)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				return fmt.Errorf("skill '%s' already exists for user", skill.Name)
			case "23514": // check_violation
				return fmt.Errorf("invalid proficiency level: %d", skill.Proficiency)
			}
		}
		return fmt.Errorf("failed to create skill: %w", err)
	}

	return nil
}

func (r *skillRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Skill, error) {
	query := `
		SELECT id, user_id, name, category, proficiency, created_at, updated_at
		FROM skills 
		WHERE id = $1`

	skill := &domain.Skill{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&skill.ID,
		&skill.UserID,
		&skill.Name,
		&skill.Category,
		&skill.Proficiency,
		&skill.CreatedAt,
		&skill.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("skill with id %s not found", id)
		}
		return nil, fmt.Errorf("failed to get skill: %w", err)
	}

	return skill, nil
}

func (r *skillRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Skill, error) {
	query := `
		SELECT id, user_id, name, category, proficiency, created_at, updated_at
		FROM skills 
		WHERE user_id = $1
		ORDER BY category, name`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get skills for user %s: %w", userID, err)
	}
	defer rows.Close()

	return r.scanSkills(rows)
}

func (r *skillRepository) GetByUserIDAndCategory(ctx context.Context, userID uuid.UUID, category string) ([]*domain.Skill, error) {
	query := `
		SELECT id, user_id, name, category, proficiency, created_at, updated_at
		FROM skills 
		WHERE user_id = $1 AND category = $2
		ORDER BY name`

	rows, err := r.db.QueryContext(ctx, query, userID, category)
	if err != nil {
		return nil, fmt.Errorf("failed to get skills for user %s and category %s: %w", userID, category, err)
	}
	defer rows.Close()

	return r.scanSkills(rows)
}

func (r *skillRepository) Update(ctx context.Context, skill *domain.Skill) error {
	query := `
		UPDATE skills 
		SET name = $1, category = $2, proficiency = $3, updated_at = NOW()
		WHERE id = $4 AND user_id = $5
		RETURNING updated_at`

	err := r.db.QueryRowContext(ctx, query,
		skill.Name,
		skill.Category,
		skill.Proficiency,
		skill.ID,
		skill.UserID,
	).Scan(&skill.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("skill with id %s not found for user %s", skill.ID, skill.UserID)
		}
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				return fmt.Errorf("skill '%s' already exists for user", skill.Name)
			case "23514": // check_violation
				return fmt.Errorf("invalid proficiency level: %d", skill.Proficiency)
			}
		}
		return fmt.Errorf("failed to update skill: %w", err)
	}

	return nil
}

func (r *skillRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM skills WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete skill: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("skill with id %s not found", id)
	}

	return nil
}

func (r *skillRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM skills WHERE user_id = $1`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete skills for user %s: %w", userID, err)
	}

	return nil
}

func (r *skillRepository) Exists(ctx context.Context, userID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM skills WHERE user_id = $1 AND name = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check skill existence: %w", err)
	}

	return exists, nil
}

func (r *skillRepository) scanSkills(rows *sql.Rows) ([]*domain.Skill, error) {
	var skills []*domain.Skill

	for rows.Next() {
		skill := &domain.Skill{}
		err := rows.Scan(
			&skill.ID,
			&skill.UserID,
			&skill.Name,
			&skill.Category,
			&skill.Proficiency,
			&skill.CreatedAt,
			&skill.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan skill: %w", err)
		}
		skills = append(skills, skill)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return skills, nil
}
