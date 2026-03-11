// Package analyzer provides secret detection functionality.
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
)

// SecretDetector scans content for secrets using configured rules.
type SecretDetector struct {
	cfg             *config.Config
	compiledRules   map[string]*CompiledDetectorRule
	falsePositives  []*regexp.Regexp
	excludePatterns []*regexp.Regexp
}

// CompiledDetectorRule represents a rule with a compiled regex pattern.
type CompiledDetectorRule struct {
	Rule  *config.Rule
	Regex *regexp.Regexp
}

// NewSecretDetector creates a new SecretDetector instance.
func NewSecretDetector(cfg *config.Config) (*SecretDetector, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	sd := &SecretDetector{
		cfg:           cfg,
		compiledRules: make(map[string]*CompiledDetectorRule),
	}

	// Compile all regex patterns
	for i := range cfg.Rules {
		re, err := regexp.Compile(cfg.Rules[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex for rule %s: %w", cfg.Rules[i].Name, err)
		}

		sd.compiledRules[cfg.Rules[i].Name] = &CompiledDetectorRule{
			Rule:  &cfg.Rules[i],
			Regex: re,
		}
	}

	// Pre-compile false positive patterns
	for _, pattern := range cfg.FalsePositives.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile false positive regex %q: %w", pattern, err)
		}
		sd.falsePositives = append(sd.falsePositives, re)
	}

	// Pre-compile exclude patterns
	for _, pattern := range cfg.Excludes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile exclude pattern %q: %w", pattern, err)
		}
		sd.excludePatterns = append(sd.excludePatterns, re)
	}

	return sd, nil
}

// ScanContent scans content for secrets.
func (sd *SecretDetector) ScanContent(
	ctx context.Context,
	content []byte,
	filePath string,
	commitHash string,
	author string,
	message string,
) []Finding {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// Check if file should be excluded
	if sd.isExcluded(filePath) {
		return nil
	}

	var findings []Finding
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	for lineNum, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		// Skip empty lines and comments
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check each rule
		for _, compiledRule := range sd.compiledRules {
			if matches := compiledRule.Regex.FindAllStringSubmatchIndex(line, -1); matches != nil {
				for _, match := range matches {
					finding := sd.createFinding(
						compiledRule.Rule,
						filePath,
						commitHash,
						author,
						message,
						lineNum+1,
						line,
						match,
					)

					// Apply filters
					if !sd.shouldFilterOut(finding) {
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// createFinding creates a Finding from a matched pattern.
func (sd *SecretDetector) createFinding(
	rule *config.Rule,
	filePath string,
	commitHash string,
	author string,
	message string,
	lineNum int,
	line string,
	match []int,
) Finding {
	// Extract matched text.
	// If regex has exactly one capture group, use it as the secret value else keep full match
	matchedText := line[match[0]:match[1]]
	if len(match) == 4 && match[2] != -1 {
		matchedText = line[match[2]:match[3]]
	}

	// Create masked value (show only first and last characters)
	maskedValue := sd.maskValue(matchedText)

	severity := sd.priorityToSeverity(rule.Priority)

	return Finding{
		Type:          rule.Name,
		Rule:          rule.Name,
		FilePath:      filePath,
		CommitHash:    commitHash,
		CommitAuthor:  author,
		CommitMessage: message,
		LineNumber:    lineNum,
		LineContent:   line,
		Value:         matchedText,
		MaskedValue:   maskedValue,
		Severity:      severity,
		Timestamp:     time.Now(),
	}
}

// isExcluded checks if a file path should be excluded from scanning.
func (sd *SecretDetector) isExcluded(filePath string) bool {
	// Normalize path separators for consistent matching
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")

	for _, pattern := range sd.excludePatterns {
		if pattern.MatchString(normalizedPath) {
			return true
		}
	}
	return false
}

// shouldFilterOut checks if a finding should be filtered out.
func (sd *SecretDetector) shouldFilterOut(f Finding) bool {
	// Check against false positive keywords
	for _, keyword := range sd.cfg.FalsePositives.Keywords {
		if strings.Contains(strings.ToLower(f.LineContent), strings.ToLower(keyword)) {
			return true
		}
	}

	// Check against false positive patterns
	for _, re := range sd.falsePositives {
		if re.MatchString(f.LineContent) {
			return true
		}
	}

	return false
}

// maskValue creates a masked version of a secret value.
func (sd *SecretDetector) maskValue(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}

	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

// priorityToSeverity converts priority string to Severity.
func (sd *SecretDetector) priorityToSeverity(priority string) Severity {
	switch strings.ToLower(priority) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	default:
		return SeverityLow
	}
}
