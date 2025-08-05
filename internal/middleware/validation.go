package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"onePercent/pkg/utils"
)

type ValidationErrorResponse struct {
	Error   string                  `json:"error"`
	Message string                  `json:"message"`
	Details []utils.ValidationError `json:"details,omitempty"`
}

func HandleValidationError(c *gin.Context, err error) {
	if validationErrors, ok := err.(utils.ValidationErrors); ok {
		c.JSON(http.StatusBadRequest, ValidationErrorResponse{
			Error:   "validation_failed",
			Message: "Request validation failed",
			Details: validationErrors,
		})
		return
	}

	c.JSON(http.StatusBadRequest, ValidationErrorResponse{
		Error:   "validation_failed",
		Message: err.Error(),
	})
}

func ValidateJSON(model interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindJSON(model); err != nil {
			c.JSON(http.StatusBadRequest, ValidationErrorResponse{
				Error:   "invalid_json",
				Message: "Invalid JSON format: " + err.Error(),
			})
			c.Abort()
			return
		}

		if err := utils.ValidateStruct(model); err != nil {
			if validationErrors, ok := err.(utils.ValidationErrors); ok {
				c.JSON(http.StatusBadRequest, ValidationErrorResponse{
					Error:   "validation_failed",
					Message: "Request validation failed",
					Details: validationErrors,
				})
				c.Abort()
				return
			}

			c.JSON(http.StatusBadRequest, ValidationErrorResponse{
				Error:   "validation_failed",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		// Store the validated model in context for handlers to use
		c.Set("validated_model", model)
		c.Next()
	}
}

func ValidateQuery(model interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.ShouldBindQuery(model); err != nil {
			c.JSON(http.StatusBadRequest, ValidationErrorResponse{
				Error:   "invalid_query",
				Message: "Invalid query parameters: " + err.Error(),
			})
			c.Abort()
			return
		}

		if err := utils.ValidateStruct(model); err != nil {
			if validationErrors, ok := err.(utils.ValidationErrors); ok {
				c.JSON(http.StatusBadRequest, ValidationErrorResponse{
					Error:   "validation_failed",
					Message: "Query parameter validation failed",
					Details: validationErrors,
				})
				c.Abort()
				return
			}

			c.JSON(http.StatusBadRequest, ValidationErrorResponse{
				Error:   "validation_failed",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		c.Set("validated_query", model)
		c.Next()
	}
}

func ValidateUUID(paramName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		uuidStr := c.Param(paramName)
		if err := utils.ValidateField(uuidStr, "required,uuid"); err != nil {
			c.JSON(http.StatusBadRequest, ValidationErrorResponse{
				Error:   "invalid_uuid",
				Message: paramName + " must be a valid UUID",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
