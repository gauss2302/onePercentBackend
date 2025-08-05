package utils

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	validate *validator.Validate
	once     sync.Once
)

// ValidationError represents a structured validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidationErrors represents a collection of validation errors
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Message)
	}
	return strings.Join(messages, "; ")
}

// GetValidator returns a singleton instance of the validator
func GetValidator() *validator.Validate {
	once.Do(func() {
		validate = validator.New()

		// Register custom tag name function to use json tags
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})

		// Register custom validators
		registerCustomValidators()
	})

	return validate
}

// ValidateStruct validates a struct and returns formatted errors
func ValidateStruct(s interface{}) error {
	v := GetValidator()

	if err := v.Struct(s); err != nil {
		var validationErrors ValidationErrors

		for _, err := range err.(validator.ValidationErrors) {
			validationErrors = append(validationErrors, ValidationError{
				Field:   err.Field(),
				Tag:     err.Tag(),
				Value:   fmt.Sprintf("%v", err.Value()),
				Message: getErrorMessage(err),
			})
		}

		return validationErrors
	}

	return nil
}

// ValidateField validates a single field
func ValidateField(field interface{}, tag string) error {
	v := GetValidator()
	return v.Var(field, tag)
}

// registerCustomValidators registers custom validation functions
func registerCustomValidators() {
	// Register password strength validator
	validate.RegisterValidation("strong_password", validateStrongPassword)

	// Register skill category validator
	validate.RegisterValidation("skill_category", validateSkillCategory)

	// Register proficiency level validator
	validate.RegisterValidation("proficiency_level", validateProficiencyLevel)
}

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// validateSkillCategory validates skill category values
func validateSkillCategory(fl validator.FieldLevel) bool {
	category := fl.Field().String()
	validCategories := []string{"language", "framework", "tool", "database", "other"}

	for _, valid := range validCategories {
		if category == valid {
			return true
		}
	}

	return false
}

// validateProficiencyLevel validates proficiency level range
func validateProficiencyLevel(fl validator.FieldLevel) bool {
	level := fl.Field().Int()
	return level >= 0 && level <= 5
}

// getErrorMessage returns a human-readable error message
func getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", err.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", err.Field(), err.Param())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", err.Field())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", err.Field(), err.Param())
	case "strong_password":
		return fmt.Sprintf("%s must contain at least 8 characters with uppercase, lowercase, digit and special character", err.Field())
	case "skill_category":
		return fmt.Sprintf("%s must be one of: language, framework, tool, database, other", err.Field())
	case "proficiency_level":
		return fmt.Sprintf("%s must be between 0 and 5", err.Field())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", err.Field(), err.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", err.Field(), err.Param())
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}
