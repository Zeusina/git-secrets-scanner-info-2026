package validator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
)

// Validate via executing command
func (cv *CommandValidator) Validate(ctx context.Context, info SecretInfo, cfg *config.ValidationConfig) *ValidationResult {
	if cfg.Command == nil {
		return &ValidationResult{
			Status:    ValidationStatusNotValidated,
			Timestamp: time.Now(),
		}
	}

	// Parse timeout and retry delay
	timeout := 5 * time.Second
	if cfg.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Timeout); err == nil {
			timeout = d
		}
	}

	retries := 2
	if cfg.Retries > 0 {
		retries = cfg.Retries
	}

	retryDelay := 1 * time.Second
	if cfg.RetryDelay != "" {
		if d, err := time.ParseDuration(cfg.RetryDelay); err == nil {
			retryDelay = d
		}
	}

	// Template variables
	vars := TemplateVariables{
		Secret: info.Secret,
		Type:   info.Type,
		Masked: info.Masked,
	}

	// Validate configuration
	if cfg.Command.Command == "" {
		return &ValidationResult{
			Status:       ValidationStatusError,
			Timestamp:    time.Now(),
			ErrorMessage: "Command not configured",
		}
	}

	// Try to validate
	var lastResult *ValidationResult

	for attempt := 0; attempt <= retries; attempt++ {
		select {
		case <-ctx.Done():
			return &ValidationResult{
				Status:       ValidationStatusError,
				Timestamp:    time.Now(),
				ErrorMessage: "validation cancelled",
			}
		default:
		}

		result := cv.executeCommand(ctx, cfg.Command, vars, timeout)
		if result.Status != ValidationStatusError || attempt == retries {
			return result
		}

		lastResult = result

		// Wait before retry
		if attempt < retries {
			select {
			case <-ctx.Done():
				return lastResult
			case <-time.After(retryDelay):
				// Continue to next attempt
			}
		}
	}

	if lastResult != nil {
		return lastResult
	}

	return &ValidationResult{
		Status:       ValidationStatusError,
		Timestamp:    time.Now(),
		ErrorMessage: "command validation failed after retries",
	}
}

// executeCommand executes a single command
func (cv *CommandValidator) executeCommand(
	ctx context.Context,
	cmdCfg *config.CommandConfig,
	vars TemplateVariables,
	timeout time.Duration,
) *ValidationResult {
	startTime := time.Now()

	// Replace templates in command and arguments
	command := ReplaceTemplates(cmdCfg.Command, vars)
	args := ReplaceTemplatesInSlice(cmdCfg.Args, vars)

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(ctxWithTimeout, command, args...)

	// Capture output
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set environment not pass secrets via env vars for security
	cmd.Env = os.Environ()

	// Execute command
	err := cmd.Run()
	responseTime := time.Since(startTime).Milliseconds()

	// Check exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			// Command execution failed
			return &ValidationResult{
				Status:       ValidationStatusError,
				Timestamp:    time.Now(),
				ErrorMessage: fmt.Sprintf("failed to execute command: %v", err),
				ResponseTime: responseTime,
				Details:      stderr.String(),
			}
		}
	}

	// Determine status based on exit code and output
	status := determineCommandStatus(
		exitCode,
		cmdCfg.ExpectedExit,
		cmdCfg.InactiveExitCodes,
		cmdCfg.ExpectedOutput,
		stdout.String(),
	)

	return &ValidationResult{
		Status:       status,
		Timestamp:    time.Now(),
		ResponseTime: responseTime,
		Details:      stdout.String(),
	}
}

// determineCommandStatus determines validation status based on command output
func determineCommandStatus(exitCode int, expectedExit int, inactiveExitCodes []int, expectedOutput string, output string) ValidationStatus {

	// Check exit code first
	if exitCode != expectedExit {
		for _, code := range inactiveExitCodes {
			if exitCode == code {
				return ValidationStatusInactive
			}
		}
		// Any other mismatch is considered a validation error
		return ValidationStatusError
	}

	// If expectedOutput pattern is specified, check output
	if expectedOutput != "" {
		re, err := regexp.Compile(expectedOutput)
		if err != nil {
			// Invalid regex pattern = error
			return ValidationStatusError
		}

		if !re.MatchString(output) {
			// Output doesn't match expected pattern
			return ValidationStatusInactive
		}
	}

	// Everything matched
	return ValidationStatusActive
}
