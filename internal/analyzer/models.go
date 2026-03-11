// Package analyzer provides models and structures for secret detection results.
package analyzer

import (
	"time"
)

// Severity levels for detected secrets.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ValidationDetails contains information about secret validation.
type ValidationDetails struct {
	Status       string    `json:"status"`                     // not_validated, active, inactive, error
	Timestamp    time.Time `json:"timestamp"`                  // When validation was performed
	ErrorMessage string    `json:"error_message,omitempty"`    // Error details if validation failed
	HTTPStatus   int       `json:"http_status,omitempty"`      // HTTP status code for HTTP validation
	ResponseTime int64     `json:"response_time_ms,omitempty"` // Response time in milliseconds
}

// Finding represents a detected secret in the code.
type Finding struct {
	Type              string             `json:"type"`
	Rule              string             `json:"rule"`
	FilePath          string             `json:"file_path"`
	CommitHash        string             `json:"commit_hash"`
	CommitAuthor      string             `json:"commit_author"`
	CommitMessage     string             `json:"commit_message"`
	LineNumber        int                `json:"line_number"`
	LineContent       string             `json:"line_content"`
	Value             string             `json:"value"`
	MaskedValue       string             `json:"masked_value"`
	Confidence        int                `json:"confidence"` // 0-100
	Severity          Severity           `json:"severity"`
	Timestamp         time.Time          `json:"timestamp"`
	ValidationStatus  string             `json:"validation_status"`            // not_validated, active, inactive, error
	ValidationDetails *ValidationDetails `json:"validation_details,omitempty"` // Optional validation info
}

// Statistics tracks scanning statistics.
type Statistics struct {
	CommitsScanned        int
	FilesScanned          int
	FilesWithFindings     int
	FindingsCount         int
	FindingsByType        map[string]int
	FindingsBySeverity    map[Severity]int
	ValidatedCount        int // Number of findings that were validated
	ActiveSecretsCount    int // Number of active secrets
	InactiveSecretsCount  int // Number of inactive secrets
	ValidationErrorsCount int // Number of validation errors
	ScanDuration          time.Duration
	StartTime             time.Time
	EndTime               time.Time
}

// ScanResult contains the results of a security scan.
type ScanResult struct {
	Findings   []Finding
	Statistics Statistics
	Errors     []error
}

// AddFinding adds a finding to the scan result.
func (sr *ScanResult) AddFinding(f Finding) {
	// Initialize validation status if not set
	if f.ValidationStatus == "" {
		f.ValidationStatus = "not_validated"
	}

	sr.Findings = append(sr.Findings, f)
	sr.Statistics.FindingsCount++

	if sr.Statistics.FindingsByType == nil {
		sr.Statistics.FindingsByType = make(map[string]int)
	}
	sr.Statistics.FindingsByType[f.Type]++

	if sr.Statistics.FindingsBySeverity == nil {
		sr.Statistics.FindingsBySeverity = make(map[Severity]int)
	}
	sr.Statistics.FindingsBySeverity[f.Severity]++

	// Update validation statistics
	if f.ValidationStatus != "not_validated" {
		sr.Statistics.ValidatedCount++
		switch f.ValidationStatus {
		case "active":
			sr.Statistics.ActiveSecretsCount++
		case "inactive":
			sr.Statistics.InactiveSecretsCount++
		case "error":
			sr.Statistics.ValidationErrorsCount++
		}
	}
}

// AddError adds an error to the scan result.
func (sr *ScanResult) AddError(err error) {
	sr.Errors = append(sr.Errors, err)
}

// HasFindings returns true if there are any findings.
func (sr *ScanResult) HasFindings() bool {
	return len(sr.Findings) > 0
}
