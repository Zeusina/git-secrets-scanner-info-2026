// Package report provides interfaces and implementations for generating scan reports.
package report

import (
	"github.com/example/git-secrets-scanner/internal/analyzer"
)

// Reporter is the interface for generating scan reports in different formats.
type Reporter interface {
	// GenerateReport creates a formatted report from scan results.
	GenerateReport(result *analyzer.ScanResult) (string, error)
}
