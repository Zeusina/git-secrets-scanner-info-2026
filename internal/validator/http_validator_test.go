package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Zeusina/git-secrets-scanner-info-2026/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestDetermineHTTPStatus(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectedStatus int
		expected       ValidationStatus
	}{
		{
			name:           "200 OK",
			statusCode:     200,
			expectedStatus: 200,
			expected:       ValidationStatusActive,
		},
		{
			name:           "201 Created",
			statusCode:     201,
			expectedStatus: 200,
			expected:       ValidationStatusInactive,
		},
		{
			name:           "401 Unauthorized",
			statusCode:     401,
			expectedStatus: 200,
			expected:       ValidationStatusInactive,
		},
		{
			name:           "403 Forbidden",
			statusCode:     403,
			expectedStatus: 200,
			expected:       ValidationStatusInactive,
		},
		{
			name:           "404 Not Found",
			statusCode:     404,
			expectedStatus: 200,
			expected:       ValidationStatusInactive,
		},
		{
			name:           "429 Rate Limited",
			statusCode:     429,
			expectedStatus: 200,
			expected:       ValidationStatusError,
		},
		{
			name:           "500 Server Error",
			statusCode:     500,
			expectedStatus: 200,
			expected:       ValidationStatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineHTTPStatus(tt.statusCode, tt.expectedStatus)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPValidatorPerformRequest(t *testing.T) {
	validator := NewHTTPValidator()

	// Test successful request
	t.Run("successful request returns active", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer test-secret", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		vars := TemplateVariables{
			Secret: "test-secret",
			Type:   "API_KEY",
			Masked: "te**et",
		}

		ctx := context.Background()
		result := validator.performRequest(ctx, "GET", server.URL, map[string]string{
			"Authorization": "Bearer {{secret}}",
		}, "", 200, vars, 5*time.Second)

		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusActive, result.Status)
		assert.Equal(t, http.StatusOK, result.HTTPStatus)
		assert.True(t, result.ResponseTime >= 0)
	})

	// Test unauthorized request
	t.Run("401 request returns inactive", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		vars := TemplateVariables{
			Secret: "bad-secret",
			Type:   "API_KEY",
			Masked: "ba**et",
		}

		ctx := context.Background()
		result := validator.performRequest(ctx, "GET", server.URL, nil, "", 200, vars, 5*time.Second)

		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusInactive, result.Status)
		assert.Equal(t, http.StatusUnauthorized, result.HTTPStatus)
	})

	// Test request with body
	t.Run("POST request with body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		vars := TemplateVariables{
			Secret: "test-secret",
			Type:   "API_KEY",
			Masked: "te**et",
		}

		ctx := context.Background()
		result := validator.performRequest(ctx, "POST", server.URL, nil, "token={{secret}}", 200, vars, 5*time.Second)

		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusActive, result.Status)
	})

	// Test timeout
	t.Run("timeout handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		vars := TemplateVariables{
			Secret: "test-secret",
			Type:   "API_KEY",
			Masked: "te**et",
		}

		ctx := context.Background()
		result := validator.performRequest(ctx, "GET", server.URL, nil, "", 200, vars, 100*time.Millisecond)

		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusError, result.Status)
	})
}

func TestHTTPValidatorValidate(t *testing.T) {
	validator := NewHTTPValidator()

	t.Run("no HTTP configuration", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "API_KEY",
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

	t.Run("missing URL", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "API_KEY",
			Masked: "te**",
		}

		cfg := &config.ValidationConfig{
			HTTP: &config.HTTPConfig{
				URL: "",
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusError, result.Status)
		assert.Contains(t, result.ErrorMessage, "URL not configured")
	})

	t.Run("invalid template in URL", func(t *testing.T) {
		ctx := context.Background()
		info := SecretInfo{
			Secret: "test",
			Type:   "API_KEY",
			Masked: "te**",
		}

		cfg := &config.ValidationConfig{
			HTTP: &config.HTTPConfig{
				URL: "https://api.example.com?key={{invalid}}",
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusError, result.Status)
		assert.Contains(t, result.ErrorMessage, "Invalid template")
	})

	t.Run("successful validation with server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ctx := context.Background()
		info := SecretInfo{
			Secret: "test-token",
			Type:   "API_KEY",
			Masked: "te**en",
		}

		cfg := &config.ValidationConfig{
			Timeout: "5s",
			Retries: 1,
			HTTP: &config.HTTPConfig{
				URL:            server.URL + "?token={{secret}}",
				Method:         "GET",
				ExpectedStatus: 200,
			},
		}

		result := validator.Validate(ctx, info, cfg)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationStatusActive, result.Status)
	})
}
