package crypto

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock GCP KMS client
type mockGCPKMSClient struct {
	mock.Mock
}

func (m *mockGCPKMSClient) GenerateRandomBytes(ctx context.Context, req *kmspb.GenerateRandomBytesRequest, opts ...gax.CallOption) (*kmspb.GenerateRandomBytesResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.GenerateRandomBytesResponse), args.Error(1)
}

func (m *mockGCPKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.EncryptResponse), args.Error(1)
}

func (m *mockGCPKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*kmspb.DecryptResponse), args.Error(1)
}

func (m *mockGCPKMSClient) Close() error {
	return nil
}

func TestGCPKMSProvider_GetMaterial(t *testing.T) {
	// Create mock client
	mockClient := new(mockGCPKMSClient)

	// Set up test data
	keyName := "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
	plaintext := []byte("test-plaintext-key")
	ciphertext := []byte("test-encrypted-key")

	// Set up expectations
	mockClient.On("GenerateRandomBytes", mock.Anything, mock.Anything).Return(
		&kmspb.GenerateRandomBytesResponse{Data: plaintext}, nil)
	mockClient.On("Encrypt", mock.Anything, mock.Anything).Return(
		&kmspb.EncryptResponse{Ciphertext: ciphertext}, nil)

	// Create provider with mock client
	provider := &GCPKMSProvider{
		kmsClient: mockClient,
		keyName:   keyName,
		algorithm: "AES_256",
	}

	// Test GetMaterial
	goCtx := context.Background()
	cryptoCtx := CryptoContext{"purpose": "test"}
	material, err := provider.GetMaterial(goCtx, cryptoCtx)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, material)
	assert.Equal(t, plaintext, material.PlaintextKey)
	assert.Equal(t, ciphertext, material.EncryptedKey)

	// Verify expectations
	mockClient.AssertExpectations(t)
}

func TestGCPKMSProvider_DecryptMaterial(t *testing.T) {
	// Create mock client
	mockClient := new(mockGCPKMSClient)

	// Set up test data
	keyName := "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
	plaintext := []byte("test-plaintext-key")
	ciphertext := []byte("test-encrypted-key")

	// Set up expectations
	mockClient.On("Decrypt", mock.Anything, mock.MatchedBy(func(req *kmspb.DecryptRequest) bool {
		return string(req.Ciphertext) == string(ciphertext)
	})).Return(&kmspb.DecryptResponse{Plaintext: plaintext}, nil)

	// Create provider with mock client
	provider := &GCPKMSProvider{
		kmsClient: mockClient,
		keyName:   keyName,
		algorithm: "AES_256",
	}

	// Test DecryptMaterial
	goCtx := context.Background()
	cryptoCtx := CryptoContext{"purpose": "test"}
	inputMaterial := &Material{
		EncryptedKey: ciphertext,
	}
	material, err := provider.DecryptMaterial(goCtx, cryptoCtx, inputMaterial)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, material)
	assert.Equal(t, plaintext, material.PlaintextKey)
	assert.Equal(t, ciphertext, material.EncryptedKey)

	// Verify expectations
	mockClient.AssertExpectations(t)
}

func TestExtractLocationFromKeyName(t *testing.T) {
	tests := []struct {
		name     string
		keyName  string
		expected string
	}{
		{
			name:     "Valid key name",
			keyName:  "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key",
			expected: "projects/my-project/locations/global",
		},
		{
			name:     "Valid key name with region",
			keyName:  "projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key",
			expected: "projects/my-project/locations/us-central1",
		},
		{
			name:     "Invalid key name",
			keyName:  "invalid-key-name",
			expected: "projects/default-project/locations/global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLocationFromKeyName(tt.keyName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
