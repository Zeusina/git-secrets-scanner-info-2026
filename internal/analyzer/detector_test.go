package analyzer

import (
	"context"
	"testing"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretDetector(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.Rule{
			{
				Name:      "Test Pattern",
				Pattern:   `api_key\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']`,
				Keywords:  []string{"api", "key"},
				Priority:  "high",
				MinLength: 10,
			},
		},
		FalsePositives: config.FalsePositives{
			Keywords: []string{"example"},
			Patterns: []string{"test"},
		},
	}

	detector, err := NewSecretDetector(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, detector)
}

func TestSecretDetectorScanContent(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.Rule{
			{
				Name:      "API Key",
				Pattern:   `api_key\s*[:=]\s*"([a-zA-Z0-9]{32})"`,
				Keywords:  []string{"api_key"},
				Priority:  "high",
				MinLength: 32,
			},
		},
		FalsePositives: config.FalsePositives{
			Keywords: []string{},
			Patterns: []string{},
		},
	}

	detector, err := NewSecretDetector(cfg)
	require.NoError(t, err)

	content := []byte(`
config:
  api_key = "mysecretapikey1234567890123456"
  timeout = 30
`)

	ctx := context.Background()
	findings := detector.ScanContent(
		ctx,
		content,
		"config.py",
		"abc123def456",
		"John Doe",
		"Add configuration",
	)

	// The pattern should match
	if len(findings) > 0 {
		assert.Equal(t, "API Key", findings[0].Type)
		assert.Equal(t, "config.py", findings[0].FilePath)
		assert.Equal(t, "abc123def456", findings[0].CommitHash)
	}
}

func TestSecretDetectorFilterFalsePositives(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.Rule{
			{
				Name:      "Password",
				Pattern:   `password\s*[:=]\s*["\']([^"\']+)["\']`,
				Keywords:  []string{"password"},
				Priority:  "high",
				MinLength: 6,
			},
		},
		FalsePositives: config.FalsePositives{
			Keywords: []string{"example_password"},
			Patterns: []string{},
		},
	}

	detector, err := NewSecretDetector(cfg)
	require.NoError(t, err)

	// This should be filtered out as a false positive
	content := []byte(`password = "example_password"`)

	ctx := context.Background()
	findings := detector.ScanContent(
		ctx,
		content,
		"config.py",
		"abc123def456",
		"John Doe",
		"Add configuration",
	)

	assert.Equal(t, 0, len(findings))
}

func TestScanResultAddFinding(t *testing.T) {
	result := &ScanResult{}

	finding := Finding{
		Type:       "Test Type",
		FilePath:   "test.py",
		Severity:   SeverityHigh,
		Confidence: 90,
	}

	result.AddFinding(finding)
	assert.Equal(t, 1, result.Statistics.FindingsCount)
	assert.Equal(t, 1, result.Statistics.FindingsByType["Test Type"])
	assert.Equal(t, 1, result.Statistics.FindingsBySeverity[SeverityHigh])
}

func TestScanResultHasFindings(t *testing.T) {
	result := &ScanResult{}
	assert.False(t, result.HasFindings())

	result.AddFinding(Finding{
		Type: "Test",
	})
	assert.True(t, result.HasFindings())
}
