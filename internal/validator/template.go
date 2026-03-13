package validator

import (
	"regexp"
	"strings"
)

// Struct for holding template variables
type TemplateVariables struct {
	Secret string
	Type   string
	Masked string
}

// Replace templates in given string
func ReplaceTemplates(template string, vars TemplateVariables) string {
	result := template
	result = strings.ReplaceAll(result, "{{secret}}", vars.Secret)
	result = strings.ReplaceAll(result, "{{type}}", vars.Type)
	result = strings.ReplaceAll(result, "{{masked}}", vars.Masked)
	return result
}

// ReplaceTemplatesInMap replces templates in all map values
func ReplaceTemplatesInMap(m map[string]string, vars TemplateVariables) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = ReplaceTemplates(v, vars)
	}
	return result
}

// ReplaceTemplatesInSlice replaces templates in all slice elements
func ReplaceTemplatesInSlice(slice []string, vars TemplateVariables) []string {
	result := make([]string, len(slice))
	for i, v := range slice {
		result[i] = ReplaceTemplates(v, vars)
	}
	return result
}

// Check validity of the template placeholders
func IsValidTemplate(template string) bool {
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	matches := re.FindAllStringSubmatch(template, -1)
	for _, match := range matches {
		switch match[1] {
		case "secret", "type", "masked":
			// Valid placeholder
		default:
			return false
		}
	}
	return true
}
