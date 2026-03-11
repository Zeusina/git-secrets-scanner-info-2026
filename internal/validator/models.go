// Package used for validate found secrets
package validator

import (
	"time"
)

// Status of validation
type ValidationStatus string

const (
	ValidationStatusNotValidated ValidationStatus = "not_validated"
	ValidationStatusActive       ValidationStatus = "active"
	ValidationStatusInactive     ValidationStatus = "inactive"
	ValidationStatusError        ValidationStatus = "error"
)

type ValidationResult struct {
	Status       ValidationStatus
	Timestamp    time.Time
	ErrorMessage string
	HTTPStatus   int    // HTTP status code for HTTP validation
	ResponseTime int64  // Response time in milliseconds
	Details      string // Additional details about validation
}

// ValidatorConfig represents configuration for validation.
type ValidatorConfig struct {
	Timeout    time.Duration
	Retries    int
	RetryDelay time.Duration
}

// SecretInfo contains information about a secret to validate.
type SecretInfo struct {
	Secret    string // Secret value
	Type      string // Config rule name
	Masked    string // Masked version of the secret
	FilePath  string // Where the secret was found
	RuleIndex int    // Index of the rule
}
