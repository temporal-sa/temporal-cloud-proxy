package crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockAzureKeyVaultClient implements AzureKeyVaultClient for testing
type MockAzureKeyVaultClient struct {
	wrapKeyOutput []byte
	wrapKeyError  error
	unwrapOutput  []byte
	unwrapError   error
	lastKeyID     string
	lastAlgorithm string
	lastPlaintext []byte
	lastCipher    []byte
}

func (m *MockAzureKeyVaultClient) WrapKey(ctx context.Context, keyID string, algorithm string, plaintext []byte) ([]byte, error) {
	m.lastKeyID = keyID
	m.lastAlgorithm = algorithm
	m.lastPlaintext = plaintext
	return m.wrapKeyOutput, m.wrapKeyError
}

func (m *MockAzureKeyVaultClient) UnwrapKey(ctx context.Context, keyID string, algorithm string, ciphertext []byte) ([]byte, error) {
	m.lastKeyID = keyID
	m.lastAlgorithm = algorithm
	m.lastCipher = ciphertext
	return m.unwrapOutput, m.unwrapError
}

func TestNewAzureKeyVaultProvider(t *testing.T) {
	tests := []struct {
		name              string
		options           AzureKeyVaultOptions
		expectedAlgorithm string
	}{
		{
			name:              "Default Algorithm",
			options:           AzureKeyVaultOptions{KeyID: "https://myvault.vault.azure.net/keys/mykey/version1"},
			expectedAlgorithm: "RSA-OAEP-256",
		},
		{
			name:              "Custom Algorithm",
			options:           AzureKeyVaultOptions{KeyID: "https://myvault.vault.azure.net/keys/mykey/version1", Algorithm: "RSA-OAEP"},
			expectedAlgorithm: "RSA-OAEP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockAzureKeyVaultClient{
				wrapKeyOutput: []byte("test-wrapped-key"),
			}
			provider := NewAzureKeyVaultProvider(mockClient, tt.options)

			// Verify algorithm by making a call that uses it
			cryptoCtx := CryptoContext{"purpose": "test"}
			ctx := context.Background()
			_, err := provider.GetMaterial(ctx, cryptoCtx)
			require.NoError(t, err)

			assert.Equal(t, tt.options.KeyID, mockClient.lastKeyID)
			assert.Equal(t, tt.expectedAlgorithm, mockClient.lastAlgorithm)
		})
	}
}

func TestAzureKeyVaultProvider_GetMaterial(t *testing.T) {
	tests := []struct {
		name          string
		context       CryptoContext
		wrapOutput    []byte
		wrapError     error
		expectedError bool
	}{
		{
			name:          "Success",
			context:       CryptoContext{"purpose": "test"},
			wrapOutput:    []byte("test-wrapped-key"),
			wrapError:     nil,
			expectedError: false,
		},
		{
			name:          "Wrap Key Error",
			context:       CryptoContext{"purpose": "test"},
			wrapOutput:    nil,
			wrapError:     errors.New("Key Vault error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockAzureKeyVaultClient{
				wrapKeyOutput: tt.wrapOutput,
				wrapKeyError:  tt.wrapError,
			}

			provider := NewAzureKeyVaultProvider(mockClient, AzureKeyVaultOptions{
				KeyID: "https://myvault.vault.azure.net/keys/mykey/version1",
			})
			ctx := context.Background()
			material, err := provider.GetMaterial(ctx, tt.context)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, material)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, material)
				assert.Len(t, material.PlaintextKey, 32) // 256-bit key
				assert.Equal(t, tt.wrapOutput, material.EncryptedKey)

				// Verify the plaintext key was sent to WrapKey
				assert.Equal(t, material.PlaintextKey, mockClient.lastPlaintext)
				assert.Equal(t, "https://myvault.vault.azure.net/keys/mykey/version1", mockClient.lastKeyID)
				assert.Equal(t, "RSA-OAEP-256", mockClient.lastAlgorithm)
			}
		})
	}
}

func TestAzureKeyVaultProvider_DecryptMaterial(t *testing.T) {
	tests := []struct {
		name              string
		context           CryptoContext
		encryptedKey      []byte
		unwrapOutput      []byte
		unwrapError       error
		expectedPlaintext []byte
		expectedError     bool
	}{
		{
			name:              "Success",
			context:           CryptoContext{"purpose": "test"},
			encryptedKey:      []byte("test-wrapped-key"),
			unwrapOutput:      []byte("test-plaintext-key"),
			unwrapError:       nil,
			expectedPlaintext: []byte("test-plaintext-key"),
			expectedError:     false,
		},
		{
			name:              "Unwrap Key Error",
			context:           CryptoContext{"purpose": "test"},
			encryptedKey:      []byte("test-wrapped-key"),
			unwrapOutput:      nil,
			unwrapError:       errors.New("Key Vault error"),
			expectedPlaintext: nil,
			expectedError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockAzureKeyVaultClient{
				unwrapOutput: tt.unwrapOutput,
				unwrapError:  tt.unwrapError,
			}

			provider := NewAzureKeyVaultProvider(mockClient, AzureKeyVaultOptions{
				KeyID: "https://myvault.vault.azure.net/keys/mykey/version1",
			})
			inputMaterial := &Material{
				EncryptedKey: tt.encryptedKey,
			}
			ctx := context.Background()
			material, err := provider.DecryptMaterial(ctx, tt.context, inputMaterial)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, material)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPlaintext, material.PlaintextKey)
				assert.Equal(t, tt.encryptedKey, material.EncryptedKey)

				// Verify the correct ciphertext was sent to UnwrapKey
				assert.Equal(t, tt.encryptedKey, mockClient.lastCipher)
				assert.Equal(t, "https://myvault.vault.azure.net/keys/mykey/version1", mockClient.lastKeyID)
				assert.Equal(t, "RSA-OAEP-256", mockClient.lastAlgorithm)
			}
		})
	}
}

func TestAzureKeyVaultProvider_GetMaterialGeneratesUniqueKeys(t *testing.T) {
	mockClient := &MockAzureKeyVaultClient{
		wrapKeyOutput: []byte("test-wrapped-key"),
	}

	provider := NewAzureKeyVaultProvider(mockClient, AzureKeyVaultOptions{
		KeyID: "https://myvault.vault.azure.net/keys/mykey/version1",
	})

	ctx := context.Background()
	cryptoCtx := CryptoContext{"purpose": "test"}

	// Generate two materials and verify they have different plaintext keys
	material1, err := provider.GetMaterial(ctx, cryptoCtx)
	require.NoError(t, err)

	material2, err := provider.GetMaterial(ctx, cryptoCtx)
	require.NoError(t, err)

	assert.NotEqual(t, material1.PlaintextKey, material2.PlaintextKey,
		"each call should generate a unique random key")
}
