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

// Finding represents a detected secret in the code.
type Finding struct {
	Type          string    `json:"type"`
	Rule          string    `json:"rule"`
	FilePath      string    `json:"file_path"`
	CommitHash    string    `json:"commit_hash"`
	CommitAuthor  string    `json:"commit_author"`
	CommitMessage string    `json:"commit_message"`
	LineNumber    int       `json:"line_number"`
	LineContent   string    `json:"line_content"`
	MaskedValue   string    `json:"masked_value"`
	Confidence    int       `json:"confidence"` // 0-100
	Severity      Severity  `json:"severity"`
	Timestamp     time.Time `json:"timestamp"`
}

// Statistics tracks scanning statistics.
type Statistics struct {
	CommitsScanned     int
	FilesScanned       int
	FilesWithFindings  int
	FindingsCount      int
	FindingsByType     map[string]int
	FindingsBySeverity map[Severity]int
	ScanDuration       time.Duration
	StartTime          time.Time
	EndTime            time.Time
}

// ScanResult contains the results of a security scan.
type ScanResult struct {
	Findings   []Finding
	Statistics Statistics
	Errors     []error
}

// AddFinding adds a finding to the scan result.
func (sr *ScanResult) AddFinding(f Finding) {
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
}

// AddError adds an error to the scan result.
func (sr *ScanResult) AddError(err error) {
	sr.Errors = append(sr.Errors, err)
}

// HasFindings returns true if there are any findings.
func (sr *ScanResult) HasFindings() bool {
	return len(sr.Findings) > 0
}
