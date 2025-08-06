package service

import (
	"context"
	"fmt"
	"onePercent/internal/domain"
	"onePercent/pkg/utils"
	"strings"
	"time"

	"github.com/google/uuid"
)

type skillService struct {
	repository domain.SkillRepository
	validator  utils.SkillValidator
}

func NewSkillService(repository domain.SkillRepository, validator utils.SkillValidator) domain.SkillService {
	return &skillService{
		repository: repository,
		validator:  validator,
	}
}

func (s *skillService) CreateSkill(ctx context.Context, userID uuid.UUID, req *domain.CreateSkillRequest) (*domain.Skill, error) {
	if err := s.validator.ValidateCreateSkillRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if skill already exists
	exists, err := s.repository.Exists(ctx, userID, strings.TrimSpace(req.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to check skill existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("skill '%s' already exists for user", req.Name)
	}

	skill := &domain.Skill{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        strings.TrimSpace(req.Name),
		Category:    req.Category,
		Proficiency: req.Proficiency,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repository.Create(ctx, skill); err != nil {
		return nil, fmt.Errorf("failed to create skill: %w", err)
	}

	return skill, nil
}

func (s *skillService) GetUserSkills(ctx context.Context, userID uuid.UUID) ([]*domain.Skill, error) {
	skills, err := s.repository.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user skills: %w", err)
	}

	return skills, nil
}

func (s *skillService) GetUserSkillsByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*domain.Skill, error) {
	if err := s.validator.ValidateSkillCategory(category); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	skills, err := s.repository.GetByUserIDAndCategory(ctx, userID, category)
	if err != nil {
		return nil, fmt.Errorf("failed to get user skills by category: %w", err)
	}

	return skills, nil
}

func (s *skillService) UpdateSkill(ctx context.Context, userID uuid.UUID, skillID uuid.UUID, req *domain.UpdateSkillRequest) (*domain.Skill, error) {
	if err := s.validator.ValidateUpdateSkillRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get existing skill to ensure it belongs to the user
	existingSkill, err := s.repository.GetByID(ctx, skillID)
	if err != nil {
		return nil, fmt.Errorf("failed to get skill: %w", err)
	}

	if existingSkill.UserID != userID {
		return nil, fmt.Errorf("skill does not belong to user")
	}

	// Check if the new name conflicts with existing skills (excluding current skill)
	if strings.TrimSpace(req.Name) != existingSkill.Name {
		exists, err := s.repository.Exists(ctx, userID, strings.TrimSpace(req.Name))
		if err != nil {
			return nil, fmt.Errorf("failed to check skill existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("skill '%s' already exists for user", req.Name)
		}
	}

	updatedSkill := &domain.Skill{
		ID:          skillID,
		UserID:      userID,
		Name:        strings.TrimSpace(req.Name),
		Category:    req.Category,
		Proficiency: req.Proficiency,
		CreatedAt:   existingSkill.CreatedAt,
		UpdatedAt:   time.Now(),
	}

	if err := s.repository.Update(ctx, updatedSkill); err != nil {
		return nil, fmt.Errorf("failed to update skill: %w", err)
	}

	return updatedSkill, nil
}

func (s *skillService) DeleteSkill(ctx context.Context, userID uuid.UUID, skillID uuid.UUID) error {
	// Verify skill belongs to user before deleting
	skill, err := s.repository.GetByID(ctx, skillID)
	if err != nil {
		return fmt.Errorf("failed to get skill: %w", err)
	}

	if skill.UserID != userID {
		return fmt.Errorf("skill does not belong to user")
	}

	if err := s.repository.Delete(ctx, skillID); err != nil {
		return fmt.Errorf("failed to delete skill: %w", err)
	}

	return nil
}

func (s *skillService) DeleteAllUserSkills(ctx context.Context, userID uuid.UUID) error {
	if err := s.repository.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete all user skills: %w", err)
	}

	return nil
}
