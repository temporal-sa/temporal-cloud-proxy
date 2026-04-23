package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
)

// AzureKeyVaultOptions contains configuration options for AzureKeyVaultProvider
type AzureKeyVaultOptions struct {
	// KeyID is the Azure Key Vault key identifier URL
	// Format: https://{vault-name}.vault.azure.net/keys/{key-name}/{key-version}
	KeyID string

	// Algorithm is the key wrap algorithm to use (defaults to RSA-OAEP-256 if empty)
	Algorithm string
}

// AzureKeyVaultClient defines the interface for Azure Key Vault key operations
type AzureKeyVaultClient interface {
	WrapKey(ctx context.Context, keyID string, algorithm string, plaintext []byte) ([]byte, error)
	UnwrapKey(ctx context.Context, keyID string, algorithm string, ciphertext []byte) ([]byte, error)
}

// AzureKeyVaultProvider implements MaterialsManager using Azure Key Vault
type AzureKeyVaultProvider struct {
	client    AzureKeyVaultClient
	keyID     string
	algorithm string
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault-based materials manager
func NewAzureKeyVaultProvider(client AzureKeyVaultClient, options AzureKeyVaultOptions) *AzureKeyVaultProvider {
	// Set default algorithm if not provided
	algorithm := options.Algorithm
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}

	return &AzureKeyVaultProvider{
		client:    client,
		keyID:     options.KeyID,
		algorithm: algorithm,
	}
}

// GetMaterial generates new encryption materials using Azure Key Vault
func (a *AzureKeyVaultProvider) GetMaterial(ctx context.Context, cryptoCtx CryptoContext) (*Material, error) {
	// Generate a random 256-bit data key locally
	plaintextKey := make([]byte, 32)
	if _, err := rand.Read(plaintextKey); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// Wrap the data key using Azure Key Vault
	encryptedKey, err := a.client.WrapKey(ctx, a.keyID, a.algorithm, plaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap data key: %v", err)
	}

	return &Material{
		PlaintextKey: plaintextKey,
		EncryptedKey: encryptedKey,
	}, nil
}

// DecryptMaterial decrypts the encrypted key using Azure Key Vault
func (a *AzureKeyVaultProvider) DecryptMaterial(ctx context.Context, cryptoCtx CryptoContext, material *Material) (*Material, error) {
	// Unwrap the data key using Azure Key Vault
	plaintextKey, err := a.client.UnwrapKey(ctx, a.keyID, a.algorithm, material.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap data key: %v", err)
	}

	return &Material{
		PlaintextKey: plaintextKey,
		EncryptedKey: material.EncryptedKey,
	}, nil
}
