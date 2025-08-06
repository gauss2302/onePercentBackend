package handler

import (
	"fmt"
	"net/http"
	"onePercent/internal/domain"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type SkillHandler struct {
	service domain.SkillService
}

func NewSkillHandler(service domain.SkillService) *SkillHandler {
	return &SkillHandler{
		service: service,
	}
}

// RegisterRoutes registers all skill-related routes
func (h *SkillHandler) RegisterRoutes(router *gin.RouterGroup) {
	skillsRouter := router.Group("/users/:userID/skills")

	skillsRouter.POST("", h.CreateSkill)
	skillsRouter.GET("", h.GetUserSkills)
	skillsRouter.GET("/category/:category", h.GetUserSkillsByCategory)
	skillsRouter.PUT("/:skillID", h.UpdateSkill)
	skillsRouter.DELETE("/:skillID", h.DeleteSkill)
	skillsRouter.DELETE("", h.DeleteAllUserSkills)
}

func (h *SkillHandler) CreateSkill(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req domain.CreateSkillRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload"})
		return
	}

	skill, err := h.service.CreateSkill(c.Request.Context(), userID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "validation failed") ||
			strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create skill"})
		return
	}

	c.JSON(http.StatusCreated, skill)
}

func (h *SkillHandler) GetUserSkills(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	skills, err := h.service.GetUserSkills(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get skills"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"skills": skills,
		"count":  len(skills),
	})
}

func (h *SkillHandler) GetUserSkillsByCategory(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	category := c.Param("category")
	if category == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category is required"})
		return
	}

	skills, err := h.service.GetUserSkillsByCategory(c.Request.Context(), userID, category)
	if err != nil {
		if strings.Contains(err.Error(), "validation failed") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get skills by category"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"skills":   skills,
		"count":    len(skills),
		"category": category,
	})
}

func (h *SkillHandler) UpdateSkill(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	skillID, err := h.extractSkillID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req domain.UpdateSkillRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload"})
		return
	}

	skill, err := h.service.UpdateSkill(c.Request.Context(), userID, skillID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "validation failed") ||
			strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "does not belong to user") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "skill not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update skill"})
		return
	}

	c.JSON(http.StatusOK, skill)
}

func (h *SkillHandler) DeleteSkill(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	skillID, err := h.extractSkillID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.service.DeleteSkill(c.Request.Context(), userID, skillID)
	if err != nil {
		if strings.Contains(err.Error(), "does not belong to user") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "skill not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete skill"})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *SkillHandler) DeleteAllUserSkills(c *gin.Context) {
	userID, err := h.extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.service.DeleteAllUserSkills(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete all skills"})
		return
	}

	c.Status(http.StatusNoContent)
}

// Helper methods

func (h *SkillHandler) extractUserID(c *gin.Context) (uuid.UUID, error) {
	userIDStr := c.Param("userID")
	if userIDStr == "" {
		return uuid.Nil, fmt.Errorf("user ID is required")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID format")
	}

	return userID, nil
}

func (h *SkillHandler) extractSkillID(c *gin.Context) (uuid.UUID, error) {
	skillIDStr := c.Param("skillID")
	if skillIDStr == "" {
		return uuid.Nil, fmt.Errorf("skill ID is required")
	}

	skillID, err := uuid.Parse(skillIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid skill ID format")
	}

	return skillID, nil
}
