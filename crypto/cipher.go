package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptInput represents the data and contexts for encryption operations
type EncryptInput struct {
	// Plaintext is the data to be encrypted
	Plaintext []byte
	// KeyContext is the context used for key derivation
	KeyContext CryptoContext
	// PayloadContext is the context used for authentication
	PayloadContext CryptoContext
}

// DecryptInput represents the data and contexts for decryption operations
type DecryptInput struct {
	// Ciphertext is the encrypted data to be decrypted
	Ciphertext []byte
	// EncryptedKey is the encrypted key used for decryption
	EncryptedKey []byte
	// KeyContext is the context used for key derivation
	KeyContext CryptoContext
	// PayloadContext is the context used for authentication
	PayloadContext CryptoContext
}

// Cipher holds the materials manager and provides encryption/decryption methods
type Cipher struct {
	// MaterialsManager provides the cryptographic materials
	MaterialsManager MaterialsManager
}

// NewCipher creates a new Cipher with the specified materials manager
func NewCipher(mm MaterialsManager) *Cipher {
	return &Cipher{
		MaterialsManager: mm,
	}
}

// Encrypt encrypts data using AES-GCM with material from MaterialsManager using specified contexts
func (c *Cipher) Encrypt(ctx context.Context, input *EncryptInput) ([]byte, []byte, error) {
	// Get encryption material using key context
	material, err := c.MaterialsManager.GetMaterial(ctx, input.KeyContext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get encryption material: %v", err)
	}

	// Use the plaintext key for encryption
	block, err := aes.NewCipher(material.PlaintextKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Convert payload context to authentication data
	authData := ContextToBytes(input.PayloadContext)

	// Encrypt with context as additional authenticated data
	ciphertext := gcm.Seal(nonce, nonce, input.Plaintext, authData)

	return ciphertext, material.EncryptedKey, nil
}

// Decrypt decrypts AES-GCM data using material from MaterialsManager with specified contexts
func (c *Cipher) Decrypt(ctx context.Context, input *DecryptInput) ([]byte, error) {
	// Create a material with just the encrypted key
	inputMaterial := &Material{
		EncryptedKey: input.EncryptedKey,
	}

	// Get decryption material - this will increment the usage count
	material, err := c.MaterialsManager.DecryptMaterial(ctx, input.KeyContext, inputMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to get decryption material: %v", err)
	}

	// Extract nonce and ciphertext
	block, err := aes.NewCipher(material.PlaintextKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(input.Ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Convert payload context to authentication data
	authData := ContextToBytes(input.PayloadContext)

	nonce, ciphertextData := input.Ciphertext[:nonceSize], input.Ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertextData, authData)
}
