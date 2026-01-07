// Package analyzer defines errors for the analyzer module.
package analyzer

import "errors"

// Common errors for analyzer operations.
var (
	ErrInvalidConfiguration = errors.New("invalid analyzer configuration")
	ErrNoRulesDefined       = errors.New("no detection rules defined")
)
