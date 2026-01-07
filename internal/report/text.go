// Package report provides text format report generation.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/example/git-secrets-scanner/internal/analyzer"
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
			sb.WriteString(fmt.Sprintf("\n[%d] %s\n", idx+1, finding.Type))
			sb.WriteString(fmt.Sprintf("    File:       %s:%d\n", finding.FilePath, finding.LineNumber))
			sb.WriteString(fmt.Sprintf("    Commit:     %s (%s)\n", finding.CommitHash[:8], finding.CommitAuthor))
			sb.WriteString(fmt.Sprintf("    Message:    %s\n", strings.TrimSpace(finding.CommitMessage)))
			sb.WriteString(fmt.Sprintf("    Severity:   %s\n", finding.Severity))
			sb.WriteString(fmt.Sprintf("    Confidence: %d%%\n", finding.Confidence))
			sb.WriteString(fmt.Sprintf("    Value:      %s\n", finding.MaskedValue))
			sb.WriteString(fmt.Sprintf("    Line:       %s\n", tr.maskLineContent(finding)))
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

	// Use the masked value to replace in line
	// We need to find what was actually matched and replace it
	// Since we don't have the exact matched text, we'll use MaskedValue as indicator
	// and replace any long alphanumeric sequences with masked version

	// Simple approach: replace the unmasked part with asterisks
	// The MaskedValue shows first 2 and last 2 chars, so we can infer length
	maskedLen := len(finding.MaskedValue)
	if maskedLen > 4 {
		// Count asterisks to determine original length
		asterisks := 0
		for _, c := range finding.MaskedValue {
			if c == '*' {
				asterisks++
			}
		}
		// Original length is asterisks + 4 (2 at start, 2 at end)
		originalLen := asterisks + 4

		// Create a simple mask of the appropriate length
		mask := strings.Repeat("*", originalLen)

		// Try to find and replace long strings that might be the secret
		// Look for patterns like quoted strings, key=value, url components
		result := line

		// Pattern 1: quoted strings longer than threshold
		for i := 0; i < len(result)-originalLen; i++ {
			if result[i] == '"' || result[i] == '\'' {
				endQuote := strings.IndexByte(result[i+1:], result[i])
				if endQuote > 0 && endQuote >= originalLen-2 {
					quote := string(result[i])
					result = result[:i+1] + mask + quote + result[i+1+endQuote+1:]
					break
				}
			}
		}

		return result
	}

	return "[REDACTED]"
}
