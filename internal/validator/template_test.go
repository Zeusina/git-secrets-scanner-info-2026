package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceTemplates(t *testing.T) {
	vars := TemplateVariables{
		Secret: "my-secret-key",
		Type:   "API_KEY",
		Masked: "my**********ey",
	}

	tests := []struct {
		name     string
		template string
		expected string
	}{
		{
			name:     "Replace secret",
			template: "https://api.example.com/validate?key={{secret}}",
			expected: "https://api.example.com/validate?key=my-secret-key",
		},
		{
			name:     "Replace type",
			template: "Invalid {{type}} detected",
			expected: "Invalid API_KEY detected",
		},
		{
			name:     "Replace masked",
			template: "Found: {{masked}}",
			expected: "Found: my**********ey",
		},
		{
			name:     "Multiple replacements",
			template: "Type: {{type}}, Masked: {{masked}}, Secret: {{secret}}",
			expected: "Type: API_KEY, Masked: my**********ey, Secret: my-secret-key",
		},
		{
			name:     "No replacements needed",
			template: "Plain text",
			expected: "Plain text",
		},
		{
			name:     "Empty template",
			template: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReplaceTemplates(tt.template, vars)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReplaceTemplatesInMap(t *testing.T) {
	vars := TemplateVariables{
		Secret: "secret123",
		Type:   "PassKey",
		Masked: "se**key",
	}

	m := map[string]string{
		"url":    "https://example.com?token={{secret}}",
		"auth":   "Bearer {{secret}}",
		"report": "Found {{type}} in system",
	}

	result := ReplaceTemplatesInMap(m, vars)

	assert.Equal(t, "https://example.com?token=secret123", result["url"])
	assert.Equal(t, "Bearer secret123", result["auth"])
	assert.Equal(t, "Found PassKey in system", result["report"])
}

func TestReplaceTemplatesInSlice(t *testing.T) {
	vars := TemplateVariables{
		Secret: "token-xyz",
		Type:   "API_TOKEN",
		Masked: "to**xyz",
	}

	slice := []string{
		"--token={{secret}}",
		"--type={{type}}",
		"--masked={{masked}}",
	}

	result := ReplaceTemplatesInSlice(slice, vars)

	assert.Equal(t, 3, len(result))
	assert.Equal(t, "--token=token-xyz", result[0])
	assert.Equal(t, "--type=API_TOKEN", result[1])
	assert.Equal(t, "--masked=to**xyz", result[2])
}

func TestIsValidTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		isValid  bool
	}{
		{
			name:     "Valid secret template",
			template: "https://api.example.com?key={{secret}}",
			isValid:  true,
		},
		{
			name:     "Valid type template",
			template: "Type: {{type}}",
			isValid:  true,
		},
		{
			name:     "Valid masked template",
			template: "Value: {{masked}}",
			isValid:  true,
		},
		{
			name:     "Invalid placeholder",
			template: "Invalid: {{invalid}}",
			isValid:  false,
		},
		{
			name:     "No placeholders",
			template: "Plain text",
			isValid:  true,
		},
		{
			name:     "Mixed valid placeholders",
			template: "Type: {{type}}, Secret: {{secret}}, Masked: {{masked}}",
			isValid:  true,
		},
		{
			name:     "One valid one invalid",
			template: "Type: {{type}}, Invalid: {{bad}}",
			isValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidTemplate(tt.template)
			assert.Equal(t, tt.isValid, result)
		})
	}
}
