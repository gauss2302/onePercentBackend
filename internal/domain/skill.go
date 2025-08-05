package domain

import (
	"context"
	"github.com/google/uuid"
	"time"
)

// Skill represents a user's skill with proficiency level
type Skill struct {
	ID          uuid.UUID `json:"id" db:"id"`
	UserID      uuid.UUID `json:"user_id" db:"user_id" validate:"required,uuid"`
	Name        string    `json:"name" db:"name" validate:"required,min=1,max=100"`
	Category    string    `json:"category" db:"category" validate:"required,skill_category"`
	Proficiency int       `json:"proficiency" db:"proficiency" validate:"proficiency_level"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// CreateSkillRequest represents the request to create a new skill
type CreateSkillRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Category    string `json:"category" validate:"required,skill_category"`
	Proficiency int    `json:"proficiency" validate:"proficiency_level"`
}

// UpdateSkillRequest represents the request to update a skill
type UpdateSkillRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Category    string `json:"category" validate:"required,skill_category"`
	Proficiency int    `json:"proficiency" validate:"proficiency_level"`
}

type SkillCategory string

const (
	SkillCategoryLanguage  SkillCategory = "language"
	SkillCategoryFramework SkillCategory = "framework"
	SkillCategoryTool      SkillCategory = "tool"
	SkillCategoryDatabase  SkillCategory = "database"
	SkillCategoryOther     SkillCategory = "other"
)

func (sc SkillCategory) IsValid() bool {
	switch sc {
	case SkillCategoryLanguage, SkillCategoryFramework, SkillCategoryTool, SkillCategoryDatabase, SkillCategoryOther:
		return true
	}
	return false
}

func (sc SkillCategory) String() string {
	return string(sc)
}

type ProficiencyLevel int

const (
	ProficiencyNotSet       ProficiencyLevel = 0
	ProficiencyBeginner     ProficiencyLevel = 1
	ProficiencyNovice       ProficiencyLevel = 2
	ProficiencyIntermediate ProficiencyLevel = 3
	ProficiencyAdvanced     ProficiencyLevel = 4
	ProficiencyExpert       ProficiencyLevel = 5
)

// IsValid checks if the proficiency level is valid
func (pl ProficiencyLevel) IsValid() bool {
	return pl >= ProficiencyNotSet && pl <= ProficiencyExpert
}

func (pl ProficiencyLevel) String() string {
	switch pl {
	case ProficiencyNotSet:
		return "not_set"
	case ProficiencyBeginner:
		return "beginner"
	case ProficiencyNovice:
		return "novice"
	case ProficiencyIntermediate:
		return "intermediate"
	case ProficiencyAdvanced:
		return "advanced"
	case ProficiencyExpert:
		return "expert"
	default:
		return "unknown"
	}
}

type SkillRepository interface {
	Create(ctx context.Context, skill *Skill) error
	GetByID(ctx context.Context, id uuid.UUID) (*Skill, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*Skill, error)
	GetByUserIDAndCategory(ctx context.Context, userID uuid.UUID, category string) ([]*Skill, error)
	Update(ctx context.Context, skill *Skill) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	Exists(ctx context.Context, userID uuid.UUID, name string) (bool, error)
}

type SkillService interface {
	CreateSkill(ctx context.Context, userID uuid.UUID, req *CreateSkillRequest) (*Skill, error)
	GetUserSkills(ctx context.Context, userID uuid.UUID) ([]*Skill, error)
	GetUserSkillsByCategory(ctx context.Context, userID uuid.UUID, category string) ([]*Skill, error)
	UpdateSkill(ctx context.Context, userID uuid.UUID, skillID uuid.UUID, req *UpdateSkillRequest) (*Skill, error)
	DeleteSkill(ctx context.Context, userID uuid.UUID, skillID uuid.UUID) error
	DeleteAllUserSkills(ctx context.Context, userID uuid.UUID) error
}
