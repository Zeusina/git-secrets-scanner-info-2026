// Package report provides JSON format report generation.
package report

import (
	"encoding/json"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/analyzer"
)

// JSONReporter generates machine-readable JSON reports.
type JSONReporter struct{}

// NewJSONReporter creates a new JSONReporter instance.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// GenerateReport generates a JSON formatted report.
func (jr *JSONReporter) GenerateReport(result *analyzer.ScanResult) (string, error) {
	// Create a JSON-serializable version of the result
	jsonResult := struct {
		Statistics *analyzer.Statistics `json:"statistics"`
		Findings   []analyzer.Finding   `json:"findings"`
		Errors     []string             `json:"errors"`
	}{
		Statistics: &result.Statistics,
		Findings:   result.Findings,
		Errors:     make([]string, 0),
	}

	// Convert errors to strings
	for _, err := range result.Errors {
		jsonResult.Errors = append(jsonResult.Errors, err.Error())
	}

	data, err := json.MarshalIndent(jsonResult, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
