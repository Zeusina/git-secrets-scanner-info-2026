// Package config handles loading and parsing of the secret detection rules configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule represents a single secret detection rule.
type Rule struct {
	Name      string   `yaml:"name"`
	Pattern   string   `yaml:"pattern"`
	Keywords  []string `yaml:"keywords"`
	Priority  string   `yaml:"priority"`
	MinLength int      `yaml:"min_length"`
}

// FalsePositives contains filters to reduce false positives.
type FalsePositives struct {
	Keywords []string `yaml:"keywords"`
	Patterns []string `yaml:"patterns"`
}

// Config represents the complete configuration for secret scanning.
type Config struct {
	Rules          []Rule         `yaml:"rules"`
	FalsePositives FalsePositives `yaml:"false_positives"`
	parsedPatterns map[string]*CompiledRule
}

// CompiledRule represents a rule with a pre-compiled regex pattern.
type CompiledRule struct {
	Rule          *Rule
	CompiledRegex string // Pattern as-is for pre-compilation in detector
}

// LoadConfig loads configuration from a YAML file.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.parsedPatterns = make(map[string]*CompiledRule)
	for i := range cfg.Rules {
		cfg.parsedPatterns[cfg.Rules[i].Name] = &CompiledRule{
			Rule:          &cfg.Rules[i],
			CompiledRegex: cfg.Rules[i].Pattern,
		}
	}

	return cfg, nil
}

// GetCompiledRules returns all compiled rules.
func (c *Config) GetCompiledRules() map[string]*CompiledRule {
	return c.parsedPatterns
}

// ValidateConfig validates that the configuration contains required fields.
func (c *Config) ValidateConfig() error {
	if len(c.Rules) == 0 {
		return fmt.Errorf("no rules defined in configuration")
	}

	for i := range c.Rules {
		if c.Rules[i].Name == "" {
			return fmt.Errorf("rule name is empty")
		}
		if c.Rules[i].Pattern == "" {
			return fmt.Errorf("rule pattern is empty for rule: %s", c.Rules[i].Name)
		}
		if c.Rules[i].Priority == "" {
			c.Rules[i].Priority = "medium"
		}
		if c.Rules[i].MinLength == 0 {
			c.Rules[i].MinLength = 10
		}
	}

	return nil
}
