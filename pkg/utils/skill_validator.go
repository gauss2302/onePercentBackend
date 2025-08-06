package utils

import (
	"fmt"
	"onePercent/internal/domain"
	"strings"
)

type SkillValidator interface {
	ValidateCreateSkillRequest(req *domain.CreateSkillRequest) error
	ValidateUpdateSkillRequest(req *domain.UpdateSkillRequest) error
	ValidateSkillCategory(category string) error
	ValidateProficiencyLevel(proficiency int) error
}

type skillValidator struct{}

func NewSkillValidator() SkillValidator {
	return &skillValidator{}
}

func (v *skillValidator) ValidateCreateSkillRequest(req *domain.CreateSkillRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if err := v.validateName(req.Name); err != nil {
		return err
	}

	if err := v.ValidateSkillCategory(req.Category); err != nil {
		return err
	}

	if err := v.ValidateProficiencyLevel(req.Proficiency); err != nil {
		return err
	}

	return nil
}

func (v *skillValidator) ValidateUpdateSkillRequest(req *domain.UpdateSkillRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if err := v.validateName(req.Name); err != nil {
		return err
	}

	if err := v.ValidateSkillCategory(req.Category); err != nil {
		return err
	}

	if err := v.ValidateProficiencyLevel(req.Proficiency); err != nil {
		return err
	}

	return nil
}

func (v *skillValidator) ValidateSkillCategory(category string) error {
	if strings.TrimSpace(category) == "" {
		return fmt.Errorf("category is required")
	}

	skillCategory := domain.SkillCategory(category)
	if !skillCategory.IsValid() {
		return fmt.Errorf("invalid category: %s. Valid categories are: %s",
			category,
			strings.Join(v.getValidCategories(), ", "))
	}

	return nil
}

func (v *skillValidator) ValidateProficiencyLevel(proficiency int) error {
	proficiencyLevel := domain.ProficiencyLevel(proficiency)
	if !proficiencyLevel.IsValid() {
		return fmt.Errorf("invalid proficiency level: %d. Must be between %d and %d",
			proficiency,
			int(domain.ProficiencyNotSet),
			int(domain.ProficiencyExpert))
	}

	return nil
}

func (v *skillValidator) validateName(name string) error {
	trimmedName := strings.TrimSpace(name)

	if trimmedName == "" {
		return fmt.Errorf("name is required")
	}

	if len(trimmedName) < 1 {
		return fmt.Errorf("name must be at least 1 character long")
	}

	if len(trimmedName) > 100 {
		return fmt.Errorf("name must be at most 100 characters long")
	}

	// Check for invalid characters
	if strings.Contains(trimmedName, "\n") || strings.Contains(trimmedName, "\t") {
		return fmt.Errorf("name cannot contain newlines or tabs")
	}

	return nil
}

func (v *skillValidator) getValidCategories() []string {
	return []string{
		domain.SkillCategoryLanguage.String(),
		domain.SkillCategoryFramework.String(),
		domain.SkillCategoryTool.String(),
		domain.SkillCategoryDatabase.String(),
		domain.SkillCategoryOther.String(),
	}
}
