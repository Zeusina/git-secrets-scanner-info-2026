package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "rules.yml")

	configContent := `
rules:
  - name: "Test Rule"
    pattern: 'test_pattern'
    keywords:
      - "test"
    priority: "high"
    min_length: 10

false_positives:
  keywords:
    - "example"
  patterns:
    - 'placeholder'
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Rules, 1)
	assert.Equal(t, "Test Rule", cfg.Rules[0].Name)
	assert.Equal(t, "high", cfg.Rules[0].Priority)
}

func TestLoadConfigFileNotFound(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/rules.yml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestValidateConfig(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{
				Name:      "Test",
				Pattern:   "pattern",
				Priority:  "high",
				MinLength: 10,
			},
		},
	}

	err := cfg.ValidateConfig()
	assert.NoError(t, err)
}

func TestValidateConfigEmpty(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{},
	}

	err := cfg.ValidateConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no rules defined")
}

func TestValidateConfigDefaultValues(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{
				Name:    "Test",
				Pattern: "pattern",
			},
		},
	}

	err := cfg.ValidateConfig()
	assert.NoError(t, err)
	assert.Equal(t, "medium", cfg.Rules[0].Priority)
	assert.Equal(t, 10, cfg.Rules[0].MinLength)
}
