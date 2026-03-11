package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
)

// Validate for http validation
func (hv *HTTPValidator) Validate(ctx context.Context, info SecretInfo, cfg *config.ValidationConfig) *ValidationResult {
	if cfg.HTTP == nil {
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
	if cfg.HTTP.URL == "" {
		return &ValidationResult{
			Status:       ValidationStatusError,
			Timestamp:    time.Now(),
			ErrorMessage: "HTTP URL not configured",
		}
	}

	if !IsValidTemplate(cfg.HTTP.URL) {
		return &ValidationResult{
			Status:       ValidationStatusError,
			Timestamp:    time.Now(),
			ErrorMessage: "Invalid template in HTTP URL",
		}
	}

	// Replace templates in URL
	url := ReplaceTemplates(cfg.HTTP.URL, vars)

	method := strings.ToUpper(cfg.HTTP.Method)
	if method == "" {
		method = "GET"
	}

	// Try to valudate
	var lastErr error
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

		result := hv.performRequest(ctx, method, url, cfg.HTTP.Headers, cfg.HTTP.Body, cfg.HTTP.ExpectedStatus, vars, timeout)
		if result.Status != ValidationStatusError || attempt == retries {
			return result
		}

		lastResult = result
		lastErr = fmt.Errorf(result.ErrorMessage)

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
		ErrorMessage: fmt.Sprintf("validation failed: %v", lastErr),
	}
}

// performRequest performs a single HTTP request
func (hv *HTTPValidator) performRequest(
	ctx context.Context,
	method string,
	url string,
	headers map[string]string,
	bodyTemplate string,
	expectedStatus int,
	vars TemplateVariables,
	timeout time.Duration,
) *ValidationResult {
	startTime := time.Now()

	// Create request
	var req *http.Request
	var err error

	// Replace template in body
	var body io.Reader
	if bodyTemplate != "" {
		bodyStr := ReplaceTemplates(bodyTemplate, vars)
		body = strings.NewReader(bodyStr)
	}

	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return &ValidationResult{
			Status:       ValidationStatusError,
			Timestamp:    time.Now(),
			ErrorMessage: fmt.Sprintf("failed to create request: %v", err),
		}
	}

	// Add headers
	if headers != nil {
		headersReplaced := ReplaceTemplatesInMap(headers, vars)
		for k, v := range headersReplaced {
			req.Header.Set(k, v)
		}
	}

	// Set default content type if body is present
	if bodyTemplate != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout,
	}

	// Execute request
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return &ValidationResult{
			Status:       ValidationStatusError,
			Timestamp:    time.Now(),
			ErrorMessage: fmt.Sprintf("HTTP request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response with size limit
	io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit

	responseTime := time.Since(startTime).Milliseconds()

	status := determineHTTPStatus(resp.StatusCode, expectedStatus)

	return &ValidationResult{
		Status:       status,
		Timestamp:    time.Now(),
		HTTPStatus:   resp.StatusCode,
		ResponseTime: responseTime,
	}
}

// determineHTTPStatus determines validation status based on HTTP response code.
func determineHTTPStatus(statusCode int, expectedStatus int) ValidationStatus {
	// Set expected status to 200 if not specified
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	switch {
	case statusCode >= 200 && statusCode < 300:
		if statusCode == expectedStatus {
			return ValidationStatusActive
		}
		// If we got success code but not expected think that secret is inactive
		return ValidationStatusInactive
	case statusCode == 401 || statusCode == 403:
		return ValidationStatusInactive
	case statusCode == 404:
		return ValidationStatusInactive
	case statusCode == 429:
		// Rate limit is error, should retry
		return ValidationStatusError
	default:
		// Other errors
		return ValidationStatusError
	}
}
