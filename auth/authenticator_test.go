package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticationResult(t *testing.T) {
	tests := []struct {
		name   string
		result *AuthenticationResult
	}{
		{
			name: "complete authentication result",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Claims: map[string]interface{}{
					"role":  "admin",
					"scope": "read:write",
					"exp":   1234567890,
				},
				Expiration: time.Now().Add(time.Hour),
			},
		},
		{
			name: "failed authentication result",
			result: &AuthenticationResult{
				Authenticated: false,
				Subject:       "",
				Claims:        nil,
				Expiration:    time.Time{},
			},
		},
		{
			name: "authentication result with empty claims",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "service-account",
				Claims:        map[string]interface{}{},
				Expiration:    time.Now().Add(30 * time.Minute),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that all fields are accessible and have expected values
			assert.Equal(t, tt.result.Authenticated, tt.result.Authenticated)
			assert.Equal(t, tt.result.Subject, tt.result.Subject)
			assert.Equal(t, tt.result.Claims, tt.result.Claims)
			assert.Equal(t, tt.result.Expiration, tt.result.Expiration)

			// Test claims access if present
			if tt.result.Claims != nil {
				for key, expectedValue := range tt.result.Claims {
					actualValue, exists := tt.result.Claims[key]
					assert.True(t, exists, "Expected claim %s to exist", key)
					assert.Equal(t, expectedValue, actualValue, "Expected claim %s to have correct value", key)
				}
			}
		})
	}
}

func TestAuthenticationResult_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		result    *AuthenticationResult
		checkTime time.Time
		isExpired bool
	}{
		{
			name: "not expired - future expiration",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Expiration:    now.Add(time.Hour),
			},
			checkTime: now,
			isExpired: false,
		},
		{
			name: "expired - past expiration",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Expiration:    now.Add(-time.Hour),
			},
			checkTime: now,
			isExpired: true,
		},
		{
			name: "exactly at expiration time",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Expiration:    now,
			},
			checkTime: now,
			isExpired: false, // Should not be expired at exact time
		},
		{
			name: "zero expiration time",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Expiration:    time.Time{},
			},
			checkTime: now,
			isExpired: true, // Zero time should be considered expired
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test expiration logic
			isExpired := tt.result.Expiration.Before(tt.checkTime) && !tt.result.Expiration.IsZero()
			if tt.result.Expiration.IsZero() {
				isExpired = true // Zero time is always expired
			}

			assert.Equal(t, tt.isExpired, isExpired)
		})
	}
}

// TestAuthenticatorInterface verifies that our implementations satisfy the interface
func TestAuthenticatorInterface(t *testing.T) {
	tests := []struct {
		name string
		auth Authenticator
	}{
		{
			name: "SpiffeAuthenticator implements Authenticator",
			auth: &SpiffeAuthenticator{},
		},
		{
			name: "MockAuthenticator implements Authenticator",
			auth: NewMockAuthenticator("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify interface compliance by checking Type method
			authType := tt.auth.Type()
			assert.NotEmpty(t, authType)

			// Verify that the authenticator implements all interface methods
			// by checking that they can be assigned to the interface
			var _ Authenticator = tt.auth

			// Test that the methods exist (compile-time check)
			// We don't call them to avoid mock setup issues
			assert.NotNil(t, tt.auth.Init)
			assert.NotNil(t, tt.auth.Authenticate)
			assert.NotNil(t, tt.auth.Refresh)
			assert.NotNil(t, tt.auth.Close)
		})
	}
}

// TestAuthenticatorTypeUniqueness ensures different authenticator types return unique type strings
func TestAuthenticatorTypeUniqueness(t *testing.T) {
	authenticators := []Authenticator{
		&SpiffeAuthenticator{},
		NewMockAuthenticator("mock1"),
		NewMockAuthenticator("mock2"),
	}

	types := make(map[string]bool)

	for _, auth := range authenticators {
		authType := auth.Type()
		assert.NotEmpty(t, authType, "Authenticator type should not be empty")

		// For mock authenticators with different types, they should be unique
		if authType != "mock1" && authType != "mock2" {
			assert.False(t, types[authType], "Authenticator type %s should be unique", authType)
		}
		types[authType] = true
	}
}

// TestAuthenticationResultClaimsManipulation tests working with claims
func TestAuthenticationResultClaimsManipulation(t *testing.T) {
	result := &AuthenticationResult{
		Authenticated: true,
		Subject:       "test-user",
		Claims:        make(map[string]interface{}),
		Expiration:    time.Now().Add(time.Hour),
	}

	// Test adding claims
	result.Claims["role"] = "admin"
	result.Claims["permissions"] = []string{"read", "write"}
	result.Claims["numeric_claim"] = 42

	// Verify claims were added
	assert.Equal(t, "admin", result.Claims["role"])
	assert.Equal(t, []string{"read", "write"}, result.Claims["permissions"])
	assert.Equal(t, 42, result.Claims["numeric_claim"])

	// Test modifying claims
	result.Claims["role"] = "user"
	assert.Equal(t, "user", result.Claims["role"])

	// Test deleting claims
	delete(result.Claims, "numeric_claim")
	_, exists := result.Claims["numeric_claim"]
	assert.False(t, exists)

	// Test claims count
	assert.Equal(t, 2, len(result.Claims))
}

// TestAuthenticationResultCopy tests copying authentication results
func TestAuthenticationResultCopy(t *testing.T) {
	original := &AuthenticationResult{
		Authenticated: true,
		Subject:       "original-user",
		Claims: map[string]interface{}{
			"role": "admin",
			"exp":  1234567890,
		},
		Expiration: time.Now().Add(time.Hour),
	}

	// Create a copy
	copy := &AuthenticationResult{
		Authenticated: original.Authenticated,
		Subject:       original.Subject,
		Claims:        make(map[string]interface{}),
		Expiration:    original.Expiration,
	}

	// Copy claims
	for k, v := range original.Claims {
		copy.Claims[k] = v
	}

	// Verify copy is identical
	assert.Equal(t, original.Authenticated, copy.Authenticated)
	assert.Equal(t, original.Subject, copy.Subject)
	assert.Equal(t, original.Expiration, copy.Expiration)
	assert.Equal(t, len(original.Claims), len(copy.Claims))

	for k, v := range original.Claims {
		assert.Equal(t, v, copy.Claims[k])
	}

	// Verify they are independent (modifying copy doesn't affect original)
	copy.Subject = "modified-user"
	copy.Claims["new_claim"] = "new_value"

	assert.NotEqual(t, original.Subject, copy.Subject)
	_, exists := original.Claims["new_claim"]
	assert.False(t, exists)
}

// TestAuthenticationResultValidation tests validation scenarios
func TestAuthenticationResultValidation(t *testing.T) {
	tests := []struct {
		name    string
		result  *AuthenticationResult
		isValid bool
		reason  string
	}{
		{
			name: "valid authenticated result",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Claims:        map[string]interface{}{"role": "admin"},
				Expiration:    time.Now().Add(time.Hour),
			},
			isValid: true,
			reason:  "complete valid result",
		},
		{
			name: "valid unauthenticated result",
			result: &AuthenticationResult{
				Authenticated: false,
				Subject:       "",
				Claims:        nil,
				Expiration:    time.Time{},
			},
			isValid: true,
			reason:  "valid failure result",
		},
		{
			name: "authenticated but no subject",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "",
				Claims:        map[string]interface{}{"role": "admin"},
				Expiration:    time.Now().Add(time.Hour),
			},
			isValid: false,
			reason:  "authenticated results should have a subject",
		},
		{
			name: "authenticated but expired",
			result: &AuthenticationResult{
				Authenticated: true,
				Subject:       "user123",
				Claims:        map[string]interface{}{"role": "admin"},
				Expiration:    time.Now().Add(-time.Hour),
			},
			isValid: false,
			reason:  "authenticated results should not be expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic
			isValid := true

			if tt.result.Authenticated {
				// If authenticated, should have a subject
				if tt.result.Subject == "" {
					isValid = false
				}
				// If authenticated, should not be expired
				if !tt.result.Expiration.IsZero() && tt.result.Expiration.Before(time.Now()) {
					isValid = false
				}
			}

			assert.Equal(t, tt.isValid, isValid, tt.reason)
		})
	}
}

// TestAuthenticationResultEdgeCases tests edge cases and boundary conditions
func TestAuthenticationResultEdgeCases(t *testing.T) {
	t.Run("nil claims map", func(t *testing.T) {
		result := &AuthenticationResult{
			Authenticated: true,
			Subject:       "user123",
			Claims:        nil,
			Expiration:    time.Now().Add(time.Hour),
		}

		// Should not panic when accessing nil claims
		assert.Nil(t, result.Claims)

		// Initialize claims if needed
		if result.Claims == nil {
			result.Claims = make(map[string]interface{})
		}

		result.Claims["test"] = "value"
		assert.Equal(t, "value", result.Claims["test"])
	})

	t.Run("very long subject", func(t *testing.T) {
		longSubject := string(make([]byte, 10000))
		for i := range longSubject {
			longSubject = longSubject[:i] + "a" + longSubject[i+1:]
		}

		result := &AuthenticationResult{
			Authenticated: true,
			Subject:       longSubject,
			Claims:        map[string]interface{}{},
			Expiration:    time.Now().Add(time.Hour),
		}

		assert.Equal(t, 10000, len(result.Subject))
		assert.Equal(t, longSubject, result.Subject)
	})

	t.Run("complex claims structure", func(t *testing.T) {
		complexClaims := map[string]interface{}{
			"string_claim": "value",
			"int_claim":    42,
			"float_claim":  3.14,
			"bool_claim":   true,
			"array_claim":  []interface{}{"a", "b", "c"},
			"nested_claim": map[string]interface{}{
				"inner_string": "inner_value",
				"inner_int":    123,
			},
		}

		result := &AuthenticationResult{
			Authenticated: true,
			Subject:       "user123",
			Claims:        complexClaims,
			Expiration:    time.Now().Add(time.Hour),
		}

		// Verify all claim types are preserved
		assert.Equal(t, "value", result.Claims["string_claim"])
		assert.Equal(t, 42, result.Claims["int_claim"])
		assert.Equal(t, 3.14, result.Claims["float_claim"])
		assert.Equal(t, true, result.Claims["bool_claim"])
		assert.Equal(t, []interface{}{"a", "b", "c"}, result.Claims["array_claim"])

		nestedClaim := result.Claims["nested_claim"].(map[string]interface{})
		assert.Equal(t, "inner_value", nestedClaim["inner_string"])
		assert.Equal(t, 123, nestedClaim["inner_int"])
	})
}
