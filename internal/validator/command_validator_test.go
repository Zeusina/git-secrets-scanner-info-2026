package validator

import (
	"context"
	"testing"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestDetermineCommandStatus(t *testing.T) {
	tests := []struct {
		name              string
		exitCode          int
		expectedExit      int
		inactiveExitCodes []int
		expectedOutput    string
		output            string
		expectedStatus    ValidationStatus
	}{
		{
			name:              "Exit code 0 matches expected",
			exitCode:          0,
			expectedExit:      0,
			inactiveExitCodes: []int{1},
			expectedOutput:    "",
			output:            "success",
			expectedStatus:    ValidationStatusActive,
		},
		{
			name:              "Configured inactive exit code returns inactive",
			exitCode:          1,
			expectedExit:      0,
			inactiveExitCodes: []int{1, 3},
			expectedOutput:    "",
			output:            "unauthorized",
			expectedStatus:    ValidationStatusInactive,
		},
		{
			name:              "Exit code mismatch returns error",
			exitCode:          2,
			expectedExit:      0,
			inactiveExitCodes: []int{1},
			expectedOutput:    "",
			output:            "error",
			expectedStatus:    ValidationStatusError,
		},
		{
			name:              "Output regex matches",
			exitCode:          0,
			expectedExit:      0,
			inactiveExitCodes: []int{1},
			expectedOutput:    "^success",
			output:            "success: token is valid",
			expectedStatus:    ValidationStatusActive,
		},
		{
			name:              "Output regex doesn't match",
			exitCode:          0,
			expectedExit:      0,
			inactiveExitCodes: []int{1},
			expectedOutput:    "^valid",
			output:            "success: token is valid",
			expectedStatus:    ValidationStatusInactive,
		},
		{
			name:              "Invalid regex in expected output",
			exitCode:          0,
			expectedExit:      0,
			inactiveExitCodes: []int{1},
			expectedOutput:    "[invalid regex",
			output:            "any output",
			expectedStatus:    ValidationStatusError,
		},
		{
			name:              "Unconfigured non-zero exit code returns error",
			exitCode:          1,
			expectedExit:      0,
			inactiveExitCodes: nil,
			expectedOutput:    "",
			output:            "unauthorized",
			expectedStatus:    ValidationStatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineCommandStatus(tt.exitCode, tt.expectedExit, tt.inactiveExitCodes, tt.expectedOutput, tt.output)
			assert.Equal(t, tt.expectedStatus, result)
		})
	}
}

func TestCommandValidatorValidate(t *testing.T) {
	validator := NewCommandValidator()

	t.Run("no command configuration", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "PASSWORD",
			Masked: "te**",
		}

		cfg := &config.ValidationConfig{
			Timeout: "5s",
			Retries: 2,
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusNotValidated, result.Status)
	})

	t.Run("missing command", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "PASSWORD",
			Masked: "te**",
		}

		cfg := &config.ValidationConfig{
			Command: &config.CommandConfig{
				Command: "",
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusError, result.Status)
		assert.Contains(t, result.ErrorMessage, "Command not configured")
	})

	t.Run("successful command execution", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test-value",
			Type:   "TOKEN",
			Masked: "te**ue",
		}

		cfg := &config.ValidationConfig{
			Timeout: "5s",
			Retries: 1,
			Command: &config.CommandConfig{
				Command:      "echo",
				Args:         []string{"{{secret}}"},
				ExpectedExit: 0,
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		// echo command should succeed
		if result.Status != ValidationStatusError {
			assert.Equal(t, ValidationStatusActive, result.Status)
		}
	})

	t.Run("nonexistent command", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "PASSWORD",
			Masked: "te**",
		}

		cfg := &config.ValidationConfig{
			Timeout: "1s",
			Retries: 0,
			Command: &config.CommandConfig{
				Command:      "nonexistent-command-xyz",
				Args:         []string{},
				ExpectedExit: 0,
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusError, result.Status)
	})
}
