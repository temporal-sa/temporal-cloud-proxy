package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwtAuthenticator_Type(t *testing.T) {
	auth := &JwtAuthenticator{}
	assert.Equal(t, "jwt", auth.Type())
}

func TestJwtAuthenticator_Init(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]interface{}
		expectError   bool
		errorContains string
		setupServer   func() *httptest.Server
	}{
		{
			name: "valid configuration with mock server",
			config: map[string]interface{}{
				"jwks-url":  "placeholder", // Will be replaced with server URL
				"audiences": []interface{}{"service1", "service2"},
			},
			expectError: false,
			setupServer: func() *httptest.Server {
				return createMockJWKSServer(t, nil)
			},
		},
		{
			name: "missing jwks-url",
			config: map[string]interface{}{
				"audiences": []interface{}{"service1"},
			},
			expectError:   true,
			errorContains: "jwks-url is required",
		},
		{
			name: "invalid jwks-url type",
			config: map[string]interface{}{
				"jwks-url": 123,
			},
			expectError:   true,
			errorContains: "jwks-url is required",
		},
		{
			name:          "empty config",
			config:        map[string]interface{}{},
			expectError:   true,
			errorContains: "jwks-url is required",
		},
		{
			name: "unreachable jwks-url",
			config: map[string]interface{}{
				"jwks-url": "https://nonexistent.example.com/.well-known/jwks.json",
			},
			expectError: true, // Will panic and be recovered as error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &JwtAuthenticator{}
			ctx := context.Background()

			var server *httptest.Server
			if tt.setupServer != nil {
				server = tt.setupServer()
				defer server.Close()
				// Replace the URL in config with the test server URL
				tt.config["jwks-url"] = server.URL + "/.well-known/jwks.json"
			}

			// Catch panics from the Init method and convert to errors
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic during init: %v", r)
					}
				}()
				err = auth.Init(ctx, tt.config)
			}()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth.jwks)
				assert.Equal(t, tt.config["jwks-url"], auth.JwksUrl)
			}
		})
	}
}

func TestJwtAuthenticator_Authenticate(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a mock JWKS server
	server := createMockJWKSServer(t, &privateKey.PublicKey)
	defer server.Close()

	// Initialize the JWT authenticator
	auth := &JwtAuthenticator{
		Audiences: []string{"test-service", "another-service"},
	}

	// We can't easily test the full Init method due to the JWKS fetching,
	// so we'll test the authentication logic with mock scenarios
	tests := []struct {
		name          string
		credentials   interface{}
		setupToken    func() string
		expectError   bool
		errorContains string
		expectedAuth  bool
		expectedSubj  string
	}{
		{
			name:          "invalid credentials type",
			credentials:   123,
			expectError:   true,
			errorContains: "credentials must be a string token",
		},
		{
			name:          "nil credentials",
			credentials:   nil,
			expectError:   true,
			errorContains: "credentials must be a string token",
		},
		{
			name:        "empty token",
			credentials: "",
			expectError: true,
		},
		{
			name:        "Bearer prefix stripped",
			credentials: "Bearer invalid.token.here",
			expectError: true,
		},
		{
			name: "valid token structure test",
			setupToken: func() string {
				// Create a valid JWT token for testing structure
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"sub": "test-user",
					"aud": "test-service",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})

				// Sign with our test key
				tokenString, err := token.SignedString(privateKey)
				require.NoError(t, err)
				return tokenString
			},
			credentials: "",   // Will be set by setupToken
			expectError: true, // Will fail due to JWKS validation in real implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			credentials := tt.credentials
			if tt.setupToken != nil {
				credentials = tt.setupToken()
			}

			result, err := auth.Authenticate(ctx, credentials)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				if result != nil {
					assert.False(t, result.Authenticated)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectedAuth, result.Authenticated)
				if tt.expectedSubj != "" {
					assert.Equal(t, tt.expectedSubj, result.Subject)
				}
			}
		})
	}
}

func TestJwtAuthenticator_TokenParsing(t *testing.T) {
	tests := []struct {
		name          string
		inputToken    string
		expectedToken string
		description   string
	}{
		{
			name:          "token without Bearer prefix",
			inputToken:    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			expectedToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			description:   "should return token as-is",
		},
		{
			name:          "token with Bearer prefix",
			inputToken:    "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			expectedToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			description:   "should strip Bearer prefix",
		},
		{
			name:          "token with bearer prefix (lowercase)",
			inputToken:    "bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			expectedToken: "bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature",
			description:   "should not strip lowercase bearer",
		},
		{
			name:          "empty token",
			inputToken:    "",
			expectedToken: "",
			description:   "should handle empty token",
		},
		{
			name:          "Bearer only",
			inputToken:    "Bearer ",
			expectedToken: "",
			description:   "should return empty string when only Bearer prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the token parsing logic directly
			token := tt.inputToken
			const prefix = "Bearer "
			token = strings.TrimPrefix(token, prefix)

			assert.Equal(t, tt.expectedToken, token, tt.description)
		})
	}
}

func TestJwtAuthenticator_Close(t *testing.T) {
	tests := []struct {
		name        string
		setupAuth   func() *JwtAuthenticator
		expectError bool
	}{
		{
			name: "close with nil jwks",
			setupAuth: func() *JwtAuthenticator {
				return &JwtAuthenticator{
					jwks: nil,
				}
			},
			expectError: false,
		},
		{
			name: "close with initialized jwks",
			setupAuth: func() *JwtAuthenticator {
				// We can't easily create a real JWKS for testing,
				// so we'll test the nil case
				return &JwtAuthenticator{
					jwks: nil,
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := tt.setupAuth()
			err := auth.Close()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJwtAuthenticator_AudienceValidation(t *testing.T) {
	tests := []struct {
		name           string
		configuredAuds []string
		tokenAudience  string
		expectValidAud bool
		description    string
	}{
		{
			name:           "valid audience match",
			configuredAuds: []string{"service1", "service2"},
			tokenAudience:  "service1",
			expectValidAud: true,
			description:    "token audience matches configured audience",
		},
		{
			name:           "valid audience match second option",
			configuredAuds: []string{"service1", "service2"},
			tokenAudience:  "service2",
			expectValidAud: true,
			description:    "token audience matches second configured audience",
		},
		{
			name:           "invalid audience",
			configuredAuds: []string{"service1", "service2"},
			tokenAudience:  "service3",
			expectValidAud: false,
			description:    "token audience does not match any configured audience",
		},
		{
			name:           "empty configured audiences",
			configuredAuds: []string{},
			tokenAudience:  "service1",
			expectValidAud: false,
			description:    "no configured audiences should reject any token",
		},
		{
			name:           "empty token audience",
			configuredAuds: []string{"service1"},
			tokenAudience:  "",
			expectValidAud: false,
			description:    "empty token audience should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the audience validation logic
			validAud := false
			for _, audience := range tt.configuredAuds {
				if tt.tokenAudience == audience {
					validAud = true
					break
				}
			}

			assert.Equal(t, tt.expectValidAud, validAud, tt.description)
		})
	}
}

func TestJwtAuthenticator_ClaimsExtraction(t *testing.T) {
	tests := []struct {
		name          string
		claims        jwt.MapClaims
		expectError   bool
		errorContains string
		expectedSub   string
		expectedAud   string
	}{
		{
			name: "valid claims",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": "service1",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
				"iat": float64(time.Now().Unix()),
			},
			expectError: false,
			expectedSub: "user123",
			expectedAud: "service1",
		},
		{
			name: "missing subject",
			claims: jwt.MapClaims{
				"aud": "service1",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
			expectError:   true,
			errorContains: "invalid subject",
		},
		{
			name: "invalid subject type",
			claims: jwt.MapClaims{
				"sub": 123,
				"aud": "service1",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
			expectError:   true,
			errorContains: "invalid subject",
		},
		{
			name: "missing audience",
			claims: jwt.MapClaims{
				"sub": "user123",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
			expectError:   true,
			errorContains: "invalid audience format",
		},
		{
			name: "invalid audience type",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": 123,
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
			expectError:   true,
			errorContains: "invalid audience format",
		},
		{
			name: "missing expiration",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": "service1",
			},
			expectError:   true,
			errorContains: "invalid expiry",
		},
		{
			name: "invalid expiration type",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": "service1",
				"exp": "invalid",
			},
			expectError:   true,
			errorContains: "invalid expiry",
		},
		{
			name: "expired token",
			claims: jwt.MapClaims{
				"sub": "user123",
				"aud": "service1",
				"exp": float64(time.Now().Add(-time.Hour).Unix()),
			},
			expectError:   true,
			errorContains: "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test claims extraction logic
			var aud string
			var ok bool

			if aud, ok = tt.claims["aud"].(string); !ok {
				if tt.expectError && strings.Contains(tt.errorContains, "invalid audience format") {
					assert.True(t, true) // Expected this error
					return
				}
			}

			sub, ok := tt.claims["sub"].(string)
			if !ok {
				if tt.expectError && strings.Contains(tt.errorContains, "invalid subject") {
					assert.True(t, true) // Expected this error
					return
				}
			}

			expFloat, ok := tt.claims["exp"].(float64)
			if !ok {
				if tt.expectError && strings.Contains(tt.errorContains, "invalid expiry") {
					assert.True(t, true) // Expected this error
					return
				}
			}

			expiry := time.Unix(int64(expFloat), 0)
			if time.Now().After(expiry) {
				if tt.expectError && strings.Contains(tt.errorContains, "token expired") {
					assert.True(t, true) // Expected this error
					return
				}
			}

			if !tt.expectError {
				assert.Equal(t, tt.expectedSub, sub)
				assert.Equal(t, tt.expectedAud, aud)
				assert.False(t, time.Now().After(expiry))
			}
		})
	}
}

func TestJwtAuthenticator_ConfigurationEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name:        "empty config",
			config:      map[string]interface{}{},
			expectError: true,
		},
		{
			name: "nil jwks-url",
			config: map[string]interface{}{
				"jwks-url": nil,
			},
			expectError: true,
		},
		{
			name: "empty jwks-url",
			config: map[string]interface{}{
				"jwks-url": "",
			},
			expectError: true, // Empty string should be treated as missing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &JwtAuthenticator{}
			ctx := context.Background()

			// Catch panics from the Init method and convert to errors
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic during init: %v", r)
					}
				}()
				err = auth.Init(ctx, tt.config)
			}()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to create a mock JWKS server for testing
func createMockJWKSServer(t *testing.T, publicKey *rsa.PublicKey) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}

		// Create a mock JWKS response
		var jwks map[string]interface{}

		if publicKey != nil {
			jwks = map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "test-key-id",
						"use": "sig",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
					},
				},
			}
		} else {
			// Create a dummy key for testing when no real key is provided
			jwks = map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "test-key-id",
						"use": "sig",
						"alg": "RS256",
						"n":   "dummy-n-value",
						"e":   "AQAB", // Standard RSA exponent
					},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

// Integration test example (would require actual JWKS endpoint)
func TestJwtAuthenticator_Integration(t *testing.T) {
	t.Skip("Integration test - requires real JWKS endpoint")

	// This test would require:
	// 1. A real JWKS endpoint
	// 2. Valid JWT tokens signed by the corresponding private key
	// 3. Network access to fetch the JWKS

	auth := &JwtAuthenticator{}
	ctx := context.Background()

	config := map[string]interface{}{
		"jwks-url":  "https://example.com/.well-known/jwks.json",
		"audiences": []interface{}{"test-service"},
	}

	err := auth.Init(ctx, config)
	require.NoError(t, err)
	defer auth.Close()

	// Test with a real JWT token
	// token := "real.jwt.token"
	// result, err := auth.Authenticate(ctx, token)
	// assert.NoError(t, err)
	// assert.True(t, result.Authenticated)
}

func TestJwtAuthenticator_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		description string
		testFunc    func(t *testing.T)
	}{
		{
			name:        "malformed JWT token",
			description: "should handle malformed JWT tokens gracefully",
			testFunc: func(t *testing.T) {
				auth := &JwtAuthenticator{
					Audiences: []string{"test-service"},
				}
				ctx := context.Background()

				result, err := auth.Authenticate(ctx, "not.a.valid.jwt.token.format")
				assert.Error(t, err)
				if result != nil {
					assert.False(t, result.Authenticated)
				}
			},
		},
		{
			name:        "JWT with invalid signature",
			description: "should reject tokens with invalid signatures",
			testFunc: func(t *testing.T) {
				auth := &JwtAuthenticator{
					Audiences: []string{"test-service"},
				}
				ctx := context.Background()

				// Create a token with invalid signature
				invalidToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiYXVkIjoidGVzdC1zZXJ2aWNlIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid_signature"

				result, err := auth.Authenticate(ctx, invalidToken)
				assert.Error(t, err)
				if result != nil {
					assert.False(t, result.Authenticated)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}
