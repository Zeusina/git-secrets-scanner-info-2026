package validator

import (
	"context"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
)

type Validator interface {
	Validate(ctx context.Context, info SecretInfo, cfg *config.ValidationConfig) *ValidationResult
}

// Validator for Http requests
type HTTPValidator struct{}

// Validator to validate via shell commands
type CommandValidator struct{}

func NewHTTPValidator() *HTTPValidator {
	return &HTTPValidator{}
}

func NewCommandValidator() *CommandValidator {
	return &CommandValidator{}
}

// Manager for multiple parallel validations
type ValidatorOrchestrator struct {
	httpValidator    *HTTPValidator
	commandValidator *CommandValidator
	maxWorkers       int
}

func NewValidatorOrchestrator(maxWorkers int) *ValidatorOrchestrator {
	if maxWorkers <= 0 {
		maxWorkers = 5 // Default to 5 parallel validations
	}
	return &ValidatorOrchestrator{
		httpValidator:    NewHTTPValidator(),
		commandValidator: NewCommandValidator(),
		maxWorkers:       maxWorkers,
	}
}

// Validate found secrets in parallel
func (vo *ValidatorOrchestrator) ValidateFindings(
	ctx context.Context,
	findings []SecretInfo,
	rules map[string]*config.Rule,
) map[int]*ValidationResult {
	results := make(map[int]*ValidationResult)
	resultsChan := make(chan struct {
		index  int
		result *ValidationResult
	}, len(findings))
	defer close(resultsChan)

	// Using worker pool
	workerChan := make(chan int, vo.maxWorkers)
	defer close(workerChan)

	for i := 0; i < vo.maxWorkers; i++ {
		go func() {
			for idx := range workerChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				finding := findings[idx]
				if finding.RuleIndex < 0 || finding.RuleIndex >= len(findings) {
					return
				}

				var rule *config.Rule
				for _, r := range rules {
					if r.Name == finding.Type {
						rule = r
						break
					}
				}

				if rule == nil || rule.Validation == nil {
					// No validation configured for this rule
					resultsChan <- struct {
						index  int
						result *ValidationResult
					}{
						index: idx,
						result: &ValidationResult{
							Status:    ValidationStatusNotValidated,
							Timestamp: time.Now(),
						},
					}
					continue
				}

				// Validate found secret
				var result *ValidationResult
				if rule.Validation.HTTP != nil {
					result = vo.httpValidator.Validate(ctx, finding, rule.Validation)
				} else if rule.Validation.Command != nil {
					result = vo.commandValidator.Validate(ctx, finding, rule.Validation)
				} else {
					// No validator configured
					result = &ValidationResult{
						Status:    ValidationStatusNotValidated,
						Timestamp: time.Now(),
					}
				}

				if result == nil {
					result = &ValidationResult{
						Status:       ValidationStatusError,
						Timestamp:    time.Now(),
						ErrorMessage: "validation returned nil result",
					}
				}

				resultsChan <- struct {
					index  int
					result *ValidationResult
				}{
					index:  idx,
					result: result,
				}
			}
		}()
	}

	// Send work to workers
	go func() {
		for i := 0; i < len(findings); i++ {
			select {
			case <-ctx.Done():
				return
			case workerChan <- i:
			}
		}
	}()

	// Collect results
	for i := 0; i < len(findings); i++ {
		select {
		case <-ctx.Done():
			// Return partial results
			return results
		case res := <-resultsChan:
			results[res.index] = res.result
		}
	}

	return results
}
