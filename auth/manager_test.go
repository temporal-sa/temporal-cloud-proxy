package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthenticator is a mock implementation of the Authenticator interface
type MockAuthenticator struct {
	mock.Mock
	authType string
}

func NewMockAuthenticator(authType string) *MockAuthenticator {
	return &MockAuthenticator{authType: authType}
}

func (m *MockAuthenticator) Type() string {
	if m.authType != "" {
		return m.authType
	}
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthenticator) Init(ctx context.Context, config map[string]interface{}) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockAuthenticator) Authenticate(ctx context.Context, credentials interface{}) (*AuthenticationResult, error) {
	args := m.Called(ctx, credentials)
	return args.Get(0).(*AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticator) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewAuthManager(t *testing.T) {
	manager := NewAuthManager()

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.authenticators)
	assert.Equal(t, 0, len(manager.authenticators))
}

func TestAuthManager_RegisterAuthenticator(t *testing.T) {
	tests := []struct {
		name           string
		authenticators []string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "register single authenticator",
			authenticators: []string{"jwt"},
			expectError:    false,
		},
		{
			name:           "register multiple authenticators",
			authenticators: []string{"jwt", "oauth", "spiffe"},
			expectError:    false,
		},
		{
			name:           "register duplicate authenticator",
			authenticators: []string{"jwt", "jwt"},
			expectError:    true,
			errorContains:  "authenticator with type jwt already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewAuthManager()
			var err error

			for _, authType := range tt.authenticators {
				mockAuth := NewMockAuthenticator(authType)
				err = manager.RegisterAuthenticator(mockAuth)

				if tt.expectError && err != nil {
					break
				}
			}

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.authenticators), len(manager.authenticators))
			}
		})
	}
}

func TestAuthManager_GetAuthenticator(t *testing.T) {
	manager := NewAuthManager()

	// Register test authenticators
	jwtAuth := NewMockAuthenticator("jwt")
	oauthAuth := NewMockAuthenticator("oauth")

	err := manager.RegisterAuthenticator(jwtAuth)
	require.NoError(t, err)
	err = manager.RegisterAuthenticator(oauthAuth)
	require.NoError(t, err)

	tests := []struct {
		name          string
		authName      string
		expectError   bool
		errorContains string
	}{
		{
			name:        "get existing jwt authenticator",
			authName:    "jwt",
			expectError: false,
		},
		{
			name:        "get existing oauth authenticator",
			authName:    "oauth",
			expectError: false,
		},
		{
			name:          "get non-existing authenticator",
			authName:      "nonexistent",
			expectError:   true,
			errorContains: "authenticator with name nonexistent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := manager.GetAuthenticator(tt.authName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, auth)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
				assert.Equal(t, tt.authName, auth.Type())
			}
		})
	}
}

func TestAuthManager_Authenticate(t *testing.T) {
	manager := NewAuthManager()
	ctx := context.Background()

	// Setup mock authenticator
	mockAuth := NewMockAuthenticator("jwt")
	expectedResult := &AuthenticationResult{
		Authenticated: true,
		Subject:       "test-user",
		Claims:        map[string]interface{}{"role": "admin"},
		Expiration:    time.Now().Add(time.Hour),
	}

	mockAuth.On("Authenticate", ctx, "valid-token").Return(expectedResult, nil)
	mockAuth.On("Authenticate", ctx, "invalid-token").Return((*AuthenticationResult)(nil), errors.New("invalid token"))

	err := manager.RegisterAuthenticator(mockAuth)
	require.NoError(t, err)

	tests := []struct {
		name          string
		authName      string
		credentials   interface{}
		expectError   bool
		errorContains string
		expectedAuth  bool
	}{
		{
			name:         "successful authentication",
			authName:     "jwt",
			credentials:  "valid-token",
			expectError:  false,
			expectedAuth: true,
		},
		{
			name:          "failed authentication",
			authName:      "jwt",
			credentials:   "invalid-token",
			expectError:   true,
			errorContains: "invalid token",
		},
		{
			name:          "non-existing authenticator",
			authName:      "nonexistent",
			credentials:   "any-token",
			expectError:   true,
			errorContains: "authenticator with name nonexistent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := manager.Authenticate(ctx, tt.authName, tt.credentials)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectedAuth, result.Authenticated)
			}
		})
	}

	mockAuth.AssertExpectations(t)
}

func TestAuthManager_Close(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func() []*MockAuthenticator
		expectError   bool
		errorContains string
	}{
		{
			name: "close all authenticators successfully",
			setupMocks: func() []*MockAuthenticator {
				auth1 := NewMockAuthenticator("jwt")
				auth2 := NewMockAuthenticator("oauth")
				auth1.On("Close").Return(nil)
				auth2.On("Close").Return(nil)
				return []*MockAuthenticator{auth1, auth2}
			},
			expectError: false,
		},
		{
			name: "close with one authenticator error",
			setupMocks: func() []*MockAuthenticator {
				auth1 := NewMockAuthenticator("jwt")
				auth2 := NewMockAuthenticator("oauth")
				auth1.On("Close").Return(errors.New("close error"))
				auth2.On("Close").Return(nil)
				return []*MockAuthenticator{auth1, auth2}
			},
			expectError:   true,
			errorContains: "failed to close authenticator jwt",
		},
		{
			name: "close with multiple authenticator errors",
			setupMocks: func() []*MockAuthenticator {
				auth1 := NewMockAuthenticator("jwt")
				auth2 := NewMockAuthenticator("oauth")
				auth1.On("Close").Return(errors.New("jwt close error"))
				auth2.On("Close").Return(errors.New("oauth close error"))
				return []*MockAuthenticator{auth1, auth2}
			},
			expectError:   true,
			errorContains: "failed to close authenticator",
		},
		{
			name: "close empty manager",
			setupMocks: func() []*MockAuthenticator {
				return []*MockAuthenticator{}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewAuthManager()
			mocks := tt.setupMocks()

			// Register all mock authenticators
			for _, mockAuth := range mocks {
				err := manager.RegisterAuthenticator(mockAuth)
				require.NoError(t, err)
			}

			err := manager.Close()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify all mocks
			for _, mockAuth := range mocks {
				mockAuth.AssertExpectations(t)
			}
		})
	}
}

func TestAuthManager_ConcurrentAccess(t *testing.T) {
	manager := NewAuthManager()
	ctx := context.Background()

	// Setup authenticators
	numAuthenticators := 10
	var wg sync.WaitGroup

	// Concurrent registration
	wg.Add(numAuthenticators)
	for i := 0; i < numAuthenticators; i++ {
		go func(id int) {
			defer wg.Done()
			authType := fmt.Sprintf("auth-%d", id)
			mockAuth := NewMockAuthenticator(authType)
			mockAuth.On("Authenticate", mock.Anything, mock.Anything).Return(&AuthenticationResult{
				Authenticated: true,
				Subject:       fmt.Sprintf("user-%d", id),
			}, nil)

			err := manager.RegisterAuthenticator(mockAuth)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// Verify all authenticators were registered
	assert.Equal(t, numAuthenticators, len(manager.authenticators))

	// Concurrent authentication
	numRequests := 50
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer wg.Done()
			authType := fmt.Sprintf("auth-%d", id%numAuthenticators)

			result, err := manager.Authenticate(ctx, authType, "test-creds")
			assert.NoError(t, err)
			assert.True(t, result.Authenticated)
		}(i)
	}
	wg.Wait()

	// Concurrent get operations
	wg.Add(numRequests)
	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer wg.Done()
			authType := fmt.Sprintf("auth-%d", id%numAuthenticators)

			auth, err := manager.GetAuthenticator(authType)
			assert.NoError(t, err)
			assert.NotNil(t, auth)
			assert.Equal(t, authType, auth.Type())
		}(i)
	}
	wg.Wait()
}

func TestAuthManager_ThreadSafety(t *testing.T) {
	manager := NewAuthManager()
	ctx := context.Background()

	// Test concurrent read/write operations
	var wg sync.WaitGroup
	numOperations := 100

	// Concurrent registration and authentication
	wg.Add(numOperations * 2)

	for i := 0; i < numOperations; i++ {
		// Registration goroutine
		go func(id int) {
			defer wg.Done()
			authType := fmt.Sprintf("concurrent-auth-%d", id)
			mockAuth := NewMockAuthenticator(authType)
			mockAuth.On("Authenticate", mock.Anything, mock.Anything).Return(&AuthenticationResult{
				Authenticated: true,
				Subject:       fmt.Sprintf("user-%d", id),
			}, nil)

			manager.RegisterAuthenticator(mockAuth)
		}(i)

		// Authentication goroutine (may fail if authenticator not yet registered)
		go func(id int) {
			defer wg.Done()
			authType := fmt.Sprintf("concurrent-auth-%d", id)
			manager.Authenticate(ctx, authType, "test-creds")
		}(i)
	}

	wg.Wait()

	// Verify no race conditions occurred (test should not panic)
	assert.True(t, len(manager.authenticators) <= numOperations)
}
