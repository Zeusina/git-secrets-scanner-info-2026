// Package report provides text format report generation.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/analyzer"
)

// TextReporter generates human-readable text reports.
type TextReporter struct{}

// NewTextReporter creates a new TextReporter instance.
func NewTextReporter() *TextReporter {
	return &TextReporter{}
}

// GenerateReport generates a human-readable text report.
func (tr *TextReporter) GenerateReport(result *analyzer.ScanResult) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("=============================================================================\n")
	sb.WriteString("                    Git Secrets Scanner - Security Report\n")
	sb.WriteString("=============================================================================\n\n")

	// Summary statistics
	sb.WriteString("SCAN SUMMARY\n")
	sb.WriteString("-" + strings.Repeat("-", 76) + "\n")
	sb.WriteString(fmt.Sprintf("Commits scanned:        %d\n", result.Statistics.CommitsScanned))
	sb.WriteString(fmt.Sprintf("Files scanned:          %d\n", result.Statistics.FilesScanned))
	sb.WriteString(fmt.Sprintf("Files with findings:    %d\n", result.Statistics.FilesWithFindings))
	sb.WriteString(fmt.Sprintf("Total findings:         %d\n", result.Statistics.FindingsCount))
	sb.WriteString(fmt.Sprintf("Scan duration:          %v\n", result.Statistics.ScanDuration))
	sb.WriteString("\n")

	// Findings by type
	if len(result.Statistics.FindingsByType) > 0 {
		sb.WriteString("FINDINGS BY TYPE\n")
		sb.WriteString("-" + strings.Repeat("-", 76) + "\n")
		for findingType := range result.Statistics.FindingsByType {
			count := result.Statistics.FindingsByType[findingType]
			sb.WriteString(fmt.Sprintf("  %-40s: %d\n", findingType, count))
		}
		sb.WriteString("\n")
	}

	// Findings by severity
	if len(result.Statistics.FindingsBySeverity) > 0 {
		sb.WriteString("FINDINGS BY SEVERITY\n")
		sb.WriteString("-" + strings.Repeat("-", 76) + "\n")

		severities := []analyzer.Severity{
			analyzer.SeverityCritical,
			analyzer.SeverityHigh,
			analyzer.SeverityMedium,
			analyzer.SeverityLow,
		}

		for _, sev := range severities {
			if count, ok := result.Statistics.FindingsBySeverity[sev]; ok {
				sb.WriteString(fmt.Sprintf("  %-40s: %d\n", sev, count))
			}
		}
		sb.WriteString("\n")
	}

	// Validation summary
	if result.Statistics.ValidatedCount > 0 {
		sb.WriteString("VALIDATION SUMMARY\n")
		sb.WriteString("-" + strings.Repeat("-", 76) + "\n")
		sb.WriteString(fmt.Sprintf("  Total validated:       %d\n", result.Statistics.ValidatedCount))
		sb.WriteString(fmt.Sprintf("  Active secrets:        %d\n", result.Statistics.ActiveSecretsCount))
		sb.WriteString(fmt.Sprintf("  Inactive secrets:      %d\n", result.Statistics.InactiveSecretsCount))
		sb.WriteString(fmt.Sprintf("  Validation errors:     %d\n", result.Statistics.ValidationErrorsCount))
		sb.WriteString("\n")
	}

	// Detailed findings
	if len(result.Findings) > 0 {
		sb.WriteString("DETAILED FINDINGS\n")
		sb.WriteString("-" + strings.Repeat("-", 76) + "\n")

		// Sort findings by severity (critical first) and then by file/line
		sort.Slice(result.Findings, func(i, j int) bool {
			severityOrder := map[analyzer.Severity]int{
				analyzer.SeverityCritical: 0,
				analyzer.SeverityHigh:     1,
				analyzer.SeverityMedium:   2,
				analyzer.SeverityLow:      3,
			}
			if severityOrder[result.Findings[i].Severity] != severityOrder[result.Findings[j].Severity] {
				return severityOrder[result.Findings[i].Severity] < severityOrder[result.Findings[j].Severity]
			}
			return result.Findings[i].FilePath < result.Findings[j].FilePath
		})

		for idx, finding := range result.Findings {

			commitHash := finding.CommitHash
			if len(commitHash) > 8 { // Explicit check for hash len
				commitHash = commitHash[:8]
			}

			sb.WriteString(fmt.Sprintf("\n[%d] %s\n", idx+1, finding.Type))
			sb.WriteString(fmt.Sprintf("    File:       %s:%d\n", finding.FilePath, finding.LineNumber))
			sb.WriteString(fmt.Sprintf("    Commit:     %s (%s)\n", commitHash, finding.CommitAuthor))
			sb.WriteString(fmt.Sprintf("    Message:    %s\n", strings.TrimSpace(finding.CommitMessage)))
			sb.WriteString(fmt.Sprintf("    Severity:   %s\n", finding.Severity))
			sb.WriteString(fmt.Sprintf("    Confidence: %d%%\n", finding.Confidence))
			sb.WriteString(fmt.Sprintf("    Value:      %s\n", finding.MaskedValue))
			sb.WriteString(fmt.Sprintf("    Line:       %s\n", tr.maskLineContent(finding)))

			// Print validation status if validation run for this rule
			if finding.ValidationStatus != "" && finding.ValidationStatus != "not_validated" {
				sb.WriteString(fmt.Sprintf("    Validation: %s\n", finding.ValidationStatus))
				if finding.ValidationDetails != nil {
					if finding.ValidationDetails.ErrorMessage != "" {
						sb.WriteString(fmt.Sprintf("    Error:      %s\n", finding.ValidationDetails.ErrorMessage))
					}
					if finding.ValidationDetails.HTTPStatus > 0 {
						sb.WriteString(fmt.Sprintf("    HTTP Code:  %d\n", finding.ValidationDetails.HTTPStatus))
					}
					if finding.ValidationDetails.ResponseTime > 0 {
						sb.WriteString(fmt.Sprintf("    Response:   %dms\n", finding.ValidationDetails.ResponseTime))
					}
				}
			}
		}
		sb.WriteString("\n")
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("ERRORS DURING SCAN\n")
		sb.WriteString("-" + strings.Repeat("-", 76) + "\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  ⚠ %v\n", err))
		}
		sb.WriteString("\n")
	}

	// Footer
	sb.WriteString("=============================================================================\n")
	if result.Statistics.FindingsCount == 0 {
		sb.WriteString("SUCCESS: No secrets detected\n")
	} else {
		sb.WriteString("WARNING: Secrets detected! Please review and remediate.\n")
	}
	sb.WriteString("=============================================================================\n")

	return sb.String(), nil
}

// maskLineContent masks the secret value in the line content while preserving context.
func (tr *TextReporter) maskLineContent(finding analyzer.Finding) string {
	line := strings.TrimSpace(finding.LineContent)

	masked := finding.MaskedValue
	maskedLen := len(masked)
	if maskedLen < 4 {
		return "[REDACTED]" // Not enough info to locate secret
	}

	// Get prefix and suffix to display them in report
	prefix := masked[:2]
	suffix := masked[maskedLen-2:]

	for start := 0; start < len(line); {
		idx := strings.Index(line[start:], prefix)

		if idx == -1 {
			break
		}

		secretStart := start + idx

		searchFrom := secretStart + 2
		if searchFrom >= len(line) {
			break
		}

		rel := strings.Index(line[searchFrom:], suffix)
		if rel == -1 {
			break
		}

		secretEnd := searchFrom + rel + 2

		// Ensure we have at least 4 chars in the candidate
		if secretEnd-secretStart >= 4 {
			// Replace secret in candidate with masking value
			return line[:secretStart] + masked + line[secretEnd:]
		}

		start = secretStart + 1 // Move forward
	}
	// Fallback
	return "[REDACTED]"
}
