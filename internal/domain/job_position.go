package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type JobPosting struct {
    ID                  uuid.UUID                  `json:"id" db:"id"`
    CreatedAt           time.Time              `json:"created_at" db:"created_at"`
    UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
    DeletedAt           *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
    
    // Basic Job Information
    Title               string                 `json:"title" db:"title"`
    Description         string                 `json:"description" db:"description"`
    CompanyID           uuid.UUID               `json:"company_id" db:"company_id"`
    
    // Job Details
    Department          string                 `json:"department" db:"department"`
    Level               JobLevel               `json:"level" db:"level"`
    Type                JobType                `json:"type" db:"type"`
    Location            string                 `json:"location" db:"location"`
    
    // Location coordinates (stored as JSON)
    Latitude            *float64               `json:"latitude,omitempty" db:"latitude"`
    Longitude           *float64               `json:"longitude,omitempty" db:"longitude"`
    City                string                 `json:"city" db:"city"`
    State               string                 `json:"state" db:"state"`
    Country             string                 `json:"country" db:"country"`
    Timezone            string                 `json:"timezone" db:"timezone"`
    
    // Compensation
    SalaryMin           *int32                 `json:"salary_min,omitempty" db:"salary_min"`
    SalaryMax           *int32                 `json:"salary_max,omitempty" db:"salary_max"`
    SalaryCurrency      string                 `json:"salary_currency" db:"salary_currency"`
    Equity              string                 `json:"equity" db:"equity"`
    Benefits            []string               `json:"benefits" db:"benefits"`
    
    // Requirements (stored as JSON arrays)
    Requirements        []string               `json:"requirements" db:"requirements"`
    PreferredSkills     []string               `json:"preferred_skills" db:"preferred_skills"`
    ExperienceYears     *int                   `json:"experience_years,omitempty" db:"experience_years"`
    EducationLevel      EducationLevel         `json:"education_level" db:"education_level"`
    
    // Ghost Job Prevention Fields (без депозита)
    Status              JobStatus              `json:"status" db:"status"`
    VerificationLevel   VerificationLevel      `json:"verification_level" db:"verification_level"`
    
    // Hiring Pipeline Tracking
    ApplicationsCount   int                    `json:"applications_count" db:"applications_count"`
    ScreenedCount       int                    `json:"screened_count" db:"screened_count"`
    InterviewedCount    int                    `json:"interviewed_count" db:"interviewed_count"`
    OfferedCount        int                    `json:"offered_count" db:"offered_count"`
    HiredCount          int                    `json:"hired_count" db:"hired_count"`
    LastActivity        *time.Time             `json:"last_activity,omitempty" db:"last_activity"`
    
    // Timeline Management
    PostedAt            *time.Time             `json:"posted_at,omitempty" db:"posted_at"`
    ApplicationDeadline *time.Time             `json:"application_deadline,omitempty" db:"application_deadline"`
    ExpectedStartDate   *time.Time             `json:"expected_start_date,omitempty" db:"expected_start_date"`
    EstimatedFillDate   *time.Time             `json:"estimated_fill_date,omitempty" db:"estimated_fill_date"`
    ActualFillDate      *time.Time             `json:"actual_fill_date,omitempty" db:"actual_fill_date"`
    ClosedAt            *time.Time             `json:"closed_at,omitempty" db:"closed_at"`
    ClosureReason       string                 `json:"closure_reason" db:"closure_reason"`
    
    // AI Analysis Fields
    GhostJobScore       *float32               `json:"ghost_job_score,omitempty" db:"ghost_job_score"`
    QualityScore        *float32               `json:"quality_score,omitempty" db:"quality_score"`
    SimilarityHash      string                 `json:"similarity_hash" db:"similarity_hash"`
    RequirementsScore   *float32               `json:"requirements_score,omitempty" db:"requirements_score"`
    
    // Compliance & Legal
    IsH1BCompliance     bool                   `json:"is_h1b_compliance" db:"is_h1b_compliance"`
    IsEEOCCompliance    bool                   `json:"is_eeoc_compliance" db:"is_eeoc_compliance"`
    ComplianceNotes     string                 `json:"compliance_notes" db:"compliance_notes"`
    
    // Contact verification
    HRContactEmail      string                 `json:"hr_contact_email" db:"hr_contact_email"`
    HRContactPhone      string                 `json:"hr_contact_phone" db:"hr_contact_phone"`
    ContactVerified     bool                   `json:"contact_verified" db:"contact_verified"`
    ContactVerifiedAt   *time.Time             `json:"contact_verified_at,omitempty" db:"contact_verified_at"`
    
    // Simple external tracking
    ExternalID          string                 `json:"external_id" db:"external_id"`
    SourcePlatform      string                 `json:"source_platform" db:"source_platform"`
}

type JobLevel string
const (
    JobLevelIntern      JobLevel = "intern"
    JobLevelEntry       JobLevel = "entry"
    JobLevelMid         JobLevel = "mid"
    JobLevelSenior      JobLevel = "senior"
    JobLevelLead        JobLevel = "lead"
    JobLevelPrincipal   JobLevel = "principal"
    JobLevelExecutive   JobLevel = "executive"
)

type JobType string
const (
    JobTypeFullTime     JobType = "full_time"
    JobTypePartTime     JobType = "part_time"
    JobTypeContract     JobType = "contract"
    JobTypeInternship   JobType = "internship"
    JobTypeTemporary    JobType = "temporary"
)

type WorkingType string
const (
    RemoteOnsite        WorkingType = "onsite"
    RemoteRemote        WorkingType = "remote"
    RemoteHybrid        WorkingType = "hybrid"
)

type SalaryPeriod string
const (
    SalaryYearly        SalaryPeriod = "yearly"
    SalaryMonthly       SalaryPeriod = "monthly"
    SalaryWeekly        SalaryPeriod = "weekly"
    SalaryHourly        SalaryPeriod = "hourly"
)

type EducationLevel string
const (
    EducationNone       EducationLevel = "none"
    EducationHighSchool EducationLevel = "high_school"
    EducationBachelor   EducationLevel = "bachelor"
    EducationMaster     EducationLevel = "master"
    EducationPhD        EducationLevel = "phd"
)


type JobStatus string
const (
    StatusDraft         JobStatus = "draft"         // Черновик
    StatusPendingReview JobStatus = "pending"       // Ожидает модерации
    StatusActive        JobStatus = "active"        // Активная
    StatusPaused        JobStatus = "paused"        // Приостановлена
    StatusFilled        JobStatus = "filled"        // Закрыта (нанят кандидат)
    StatusCancelled     JobStatus = "cancelled"     // Отменена
    StatusFlagged       JobStatus = "flagged"       // Подозрение на ghost job
    StatusBlacklisted   JobStatus = "blacklisted"   // Заблокирована модератором
)


type VerificationLevel string
const (
    VerificationNone     VerificationLevel = "none"        // Без верификации
    VerificationBasic    VerificationLevel = "basic"       // Email verification
    VerificationStandard VerificationLevel = "standard"    // Company + contact verification
    VerificationPremium  VerificationLevel = "premium"     // Full verification + manual review
)

// Business logic methods
func (j *JobPosting) IsActive() bool {
    return j.Status == StatusActive && j.PostedAt != nil
}

func (j *JobPosting) DaysLive() int {
    if j.PostedAt == nil {
        return 0
    }
    return int(time.Since(*j.PostedAt).Hours() / 24)
}

func (j *JobPosting) HasSuspiciousActivity() bool {
    daysSincePosted := j.DaysLive()
    
    // Red flags для ghost jobs (упрощенная версия)
    if daysSincePosted > 90 && j.InterviewedCount == 0 && j.ApplicationsCount > 20 {
        return true
    }
    
    if j.ApplicationsCount > 100 && j.ScreenedCount == 0 && daysSincePosted > 30 {
        return true
    }
    
    if j.GhostJobScore != nil && *j.GhostJobScore > 0.8 {
        return true
    }
    
    // No activity за долгое время
    if j.LastActivity != nil && time.Since(*j.LastActivity).Hours() > 24*30 { // 30 days
        return true
    }
    
    return false
}

func (j *JobPosting) CalculateConversionRates() map[string]float32 {
    rates := make(map[string]float32)
    
    if j.ApplicationsCount > 0 {
        rates["application_to_screen"] = float32(j.ScreenedCount) / float32(j.ApplicationsCount)
        rates["application_to_interview"] = float32(j.InterviewedCount) / float32(j.ApplicationsCount)
        rates["application_to_hire"] = float32(j.HiredCount) / float32(j.ApplicationsCount)
    }
    
    if j.ScreenedCount > 0 {
        rates["screen_to_interview"] = float32(j.InterviewedCount) / float32(j.ScreenedCount)
    }
    
    if j.InterviewedCount > 0 {
        rates["interview_to_hire"] = float32(j.HiredCount) / float32(j.InterviewedCount)
    }
    
    return rates
}

// Validation methods для раннего стартапа
func (j *JobPosting) Validate() []string {
    var errors []string
    
    if len(j.Title) < 10 || len(j.Title) > 200 {
        errors = append(errors, "title must be between 10 and 200 characters")
    }
    
    if len(j.Description) < 100 {
        errors = append(errors, "description must be at least 100 characters")
    }
    
    if j.CompanyID == uuid.Nil {
        errors = append(errors, "company_id is required")
    }
    
    if len(j.Requirements) < 3 {
        errors = append(errors, "at least 3 requirements needed")
    }
    
    if j.HRContactEmail == "" {
        errors = append(errors, "hr_contact_email is required")
    }
    
    return errors
}

// Helper для JSON fields в PostgreSQL
func (j *JobPosting) RequirementsJSON() ([]byte, error) {
    return json.Marshal(j.Requirements)
}

func (j *JobPosting) SetRequirementsFromJSON(data []byte) error {
    return json.Unmarshal(data, &j.Requirements)
}

func (j *JobPosting) BenefitsJSON() ([]byte, error) {
    return json.Marshal(j.Benefits)
}

func (j *JobPosting) SetBenefitsFromJSON(data []byte) error {
    return json.Unmarshal(data, &j.Benefits)
}
