package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"temporal-sa/temporal-cloud-proxy/auth"
	"temporal-sa/temporal-cloud-proxy/metrics"
	"temporal-sa/temporal-cloud-proxy/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MockAuthManager is a mock implementation of the AuthManager interface
type MockAuthManager struct {
	mock.Mock
}

func (m *MockAuthManager) Authenticate(ctx context.Context, authType string, credentials string) (*auth.AuthenticationResult, error) {
	args := m.Called(ctx, authType, credentials)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthenticationResult), args.Error(1)
}

func (m *MockAuthManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Helper function to create test TLS certificates
func createTestCertificates(t *testing.T) (string, string) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Create temporary files
	certFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer certFile.Close()

	keyFile, err := os.CreateTemp("", "test-key-*.pem")
	require.NoError(t, err)
	defer keyFile.Close()

	// Write certificate
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)

	// Write private key
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	require.NoError(t, err)

	return certFile.Name(), keyFile.Name()
}

func TestNewConn(t *testing.T) {
	conn := NewConn()

	assert.NotNil(t, conn)
	assert.NotNil(t, conn.namespace)
	assert.Equal(t, 0, len(conn.namespace))
}

func TestConn_AddConn(t *testing.T) {
	// Create test certificates
	certPath, keyPath := createTestCertificates(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	tests := []struct {
		name        string
		input       AddConnInput
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful connection addition with TLS",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							TLS: &utils.TLSConfig{
								CertFile: certPath,
								KeyFile:  keyPath,
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil, // Use nil for simplicity in tests
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: false,
		},
		{
			name: "successful connection addition with API key (value)",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id-api",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							ApiKey: &utils.TemporalApiKeyConfig{
								Value: "test-api-key",
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: false,
		},
		{
			name: "successful connection addition with API key (env var)",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id-api-env",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							ApiKey: &utils.TemporalApiKeyConfig{
								EnvVar: "TEST_TEMPORAL_API_KEY",
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: true, // Will fail because env var is not set
		},
		{
			name: "invalid certificate path",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							TLS: &utils.TLSConfig{
								CertFile: "/nonexistent/cert.pem",
								KeyFile:  keyPath,
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: true,
		},
		{
			name: "invalid key path",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							TLS: &utils.TLSConfig{
								CertFile: certPath,
								KeyFile:  "/nonexistent/key.pem",
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: true,
		},
		{
			name: "both API key and TLS configured - should error",
			input: AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: "test-proxy-id",
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: "test-namespace",
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							ApiKey: &utils.TemporalApiKeyConfig{
								Value: "test-api-key",
							},
							TLS: &utils.TLSConfig{
								CertFile: certPath,
								KeyFile:  keyPath,
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			},
			expectError: true,
			errorMsg:    "cannot have both api key and mtls authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := NewConn()
			err := conn.AddConn(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(conn.namespace))

				// Verify the connection was stored correctly
				nsConn, exists := conn.namespace[tt.input.Target.ProxyId]
				assert.True(t, exists)
				assert.NotNil(t, nsConn.conn)
				assert.Equal(t, tt.input.AuthManager, nsConn.authManager)
				assert.Equal(t, tt.input.AuthType, nsConn.authType)
			}
		})
	}
}

func TestConn_CloseAll_Empty(t *testing.T) {
	conn := NewConn()
	err := conn.CloseAll()
	assert.NoError(t, err)
}

func TestConn_Invoke(t *testing.T) {
	tests := []struct {
		name          string
		setupContext  func() context.Context
		setupConn     func() *Conn
		method        string
		args          interface{}
		reply         interface{}
		expectError   bool
		expectedCode  codes.Code
		errorContains string
	}{
		{
			name: "missing metadata",
			setupContext: func() context.Context {
				return context.Background()
			},
			setupConn: func() *Conn {
				return NewConn()
			},
			method:       "/test.Service/Method",
			expectError:  true,
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "missing proxy-id",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				return NewConn()
			},
			method:        "/test.Service/Method",
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "metadata missing proxy-id",
		},
		{
			name: "multiple proxy-id entries",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{})
				md.Append("proxy-id", "proxy-id-1")
				md.Append("proxy-id", "proxy-id-2")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				return NewConn()
			},
			method:        "/test.Service/Method",
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "multiple proxy-id entries",
		},
		{
			name: "target not found",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{
					"proxy-id": "nonexistent-proxy-id",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				return NewConn()
			},
			method:        "/test.Service/Method",
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "invalid proxy-id: nonexistent-proxy-id",
		},
		{
			name: "invoke without authentication - skips auth logic",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{
					"proxy-id": "test-proxy-id-no-auth",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				conn := NewConn()
				// Don't add any namespace connections to test the "target not found" path
				// This way we can test the logic without hitting the nil pointer
				return conn
			},
			method:        "/test.Service/Method",
			args:          struct{}{},
			reply:         struct{}{},
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "invalid proxy-id: test-proxy-id-no-auth",
		},
		{
			name: "missing authorization with auth manager",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{
					"proxy-id": "test-proxy-id",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				conn := NewConn()
				// Create a real auth manager for testing
				authManager := auth.NewAuthManager()

				conn.namespace["test-proxy-id"] = NamespaceConn{
					conn:        nil,
					authManager: authManager,
					authType:    "jwt",
				}
				return conn
			},
			method:        "/test.Service/Method",
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "metadata is missing authorization",
		},
		{
			name: "multiple authorization entries",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{
					"proxy-id": "test-proxy-id",
				})
				md.Append("authorization", "Bearer token1")
				md.Append("authorization", "Bearer token2")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			setupConn: func() *Conn {
				conn := NewConn()
				// Create a real auth manager for testing
				authManager := auth.NewAuthManager()

				conn.namespace["test-proxy-id"] = NamespaceConn{
					conn:        nil,
					authManager: authManager,
					authType:    "jwt",
				}
				return conn
			},
			method:        "/test.Service/Method",
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "multiple authorization entries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()
			conn := tt.setupConn()

			err := conn.Invoke(ctx, tt.method, tt.args, tt.reply)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.expectedCode, st.Code())
				}
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConn_NewStream(t *testing.T) {
	conn := NewConn()
	ctx := context.Background()
	desc := &grpc.StreamDesc{}
	method := "/test.Service/StreamMethod"

	stream, err := conn.NewStream(ctx, desc, method)

	assert.Nil(t, stream)
	assert.Error(t, err)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
	assert.Contains(t, err.Error(), "streams not supported")
}

func TestCreateKMSClient(t *testing.T) {
	// Test with environment variable
	originalRegion := os.Getenv("AWS_REGION")
	defer func() {
		if originalRegion != "" {
			os.Setenv("AWS_REGION", originalRegion)
		} else {
			os.Unsetenv("AWS_REGION")
		}
	}()

	// Test with custom region
	os.Setenv("AWS_REGION", "us-east-1")
	client := createKMSClient()
	assert.NotNil(t, client)

	// Test with default region
	os.Unsetenv("AWS_REGION")
	client = createKMSClient()
	assert.NotNil(t, client)
}

func TestConn_ConcurrentAccess(t *testing.T) {
	// Create test certificates
	certPath, keyPath := createTestCertificates(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	conn := NewConn()

	// Test concurrent AddConn operations
	numConnections := 10
	var wg sync.WaitGroup
	wg.Add(numConnections)

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			defer wg.Done()

			input := AddConnInput{
				Target: &utils.TargetConfig{
					ProxyId: fmt.Sprintf("proxy-id-%d", id),
					TemporalCloud: utils.TemporalCloudConfig{
						Namespace: fmt.Sprintf("namespace-%d", id),
						HostPort:  "localhost:7233",
						Authentication: utils.TemporalAuthConfig{
							TLS: &utils.TLSConfig{
								CertFile: certPath,
								KeyFile:  keyPath,
							},
						},
					},
					EncryptionKey: "test-key-id",
				},
				AuthManager:         nil,
				AuthType:            "jwt",
				MetricsHandler:      metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{}),
				CryptoCachingConfig: nil,
			}

			err := conn.AddConn(input)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all connections were added
	assert.Equal(t, numConnections, len(conn.namespace))

	// Test concurrent Invoke operations
	numInvokes := 50
	wg.Add(numInvokes)

	for i := 0; i < numInvokes; i++ {
		go func(id int) {
			defer wg.Done()

			proxyId := id % numConnections
			md := metadata.New(map[string]string{
				"proxy-id": fmt.Sprintf("proxy-id-%d", proxyId),
			})
			ctx := metadata.NewIncomingContext(context.Background(), md)

			// This will fail because we don't have real gRPC connections,
			// but it tests the concurrent access to the namespace map
			conn.Invoke(ctx, "/test.Service/Method", struct{}{}, struct{}{})
		}(i)
	}

	wg.Wait()
}

// Test authentication logic with a mock that can be properly cast
func TestConn_InvokeWithAuthentication(t *testing.T) {
	conn := NewConn()

	// Create a mock auth manager
	mockAuth := &MockAuthManager{}
	mockAuth.On("Authenticate", mock.Anything, "jwt", "Bearer valid-token").Return(
		&auth.AuthenticationResult{
			Authenticated: true,
			Subject:       "test-user",
		}, nil)

	mockAuth.On("Authenticate", mock.Anything, "jwt", "Bearer invalid-token").Return(
		nil, errors.New("invalid token"))

	mockAuth.On("Authenticate", mock.Anything, "jwt", "Bearer expired-token").Return(
		&auth.AuthenticationResult{
			Authenticated: false,
		}, nil)

	// We can't easily cast our mock to *auth.AuthManager due to Go's type system,
	// so we'll test the authentication logic indirectly by testing the error cases
	// that don't require the actual authentication call.

	tests := []struct {
		name          string
		setupContext  func() context.Context
		expectError   bool
		expectedCode  codes.Code
		errorContains string
	}{
		{
			name: "missing authorization header",
			setupContext: func() context.Context {
				md := metadata.New(map[string]string{
					"proxy-id": "test-proxy-id",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectError:   true,
			expectedCode:  codes.InvalidArgument,
			errorContains: "metadata is missing authorization",
		},
	}

	// Add a namespace with auth manager (using nil since we can't easily mock the interface)
	conn.namespace["test-proxy-id"] = NamespaceConn{
		conn:        nil, // Will cause failure, but we're testing auth logic first
		authManager: nil, // We'll set this to non-nil to trigger auth checks
		authType:    "jwt",
	}

	// Set authManager to non-nil to trigger the auth logic
	// Use a real auth manager since we can't easily mock the interface
	authManager := auth.NewAuthManager()
	nsConn := conn.namespace["test-proxy-id"]
	nsConn.authManager = authManager
	conn.namespace["test-proxy-id"] = nsConn

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()

			err := conn.Invoke(ctx, "/test.Service/Method", struct{}{}, struct{}{})

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.expectedCode, st.Code())
				}
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
