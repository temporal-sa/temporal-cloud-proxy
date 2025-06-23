package crypto

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// GCPKMSOptions contains configuration options for GCPKMSProvider
type GCPKMSOptions struct {
	// KeyName is the fully qualified name of the GCP KMS key to use
	// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}
	KeyName string

	// Algorithm is the algorithm to use for encryption (defaults to AES_256 if empty)
	Algorithm string
}

// GCPKMSClient defines the interface for GCP KMS operations
type GCPKMSClient interface {
	GenerateRandomBytes(ctx context.Context, req *kmspb.GenerateRandomBytesRequest, opts ...gax.CallOption) (*kmspb.GenerateRandomBytesResponse, error)
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

// GCPKMSProvider implements MaterialsManager using Google Cloud KMS
type GCPKMSProvider struct {
	kmsClient GCPKMSClient
	// KeyName is the fully qualified name of the GCP KMS key to use
	keyName string
	// Algorithm is the algorithm to use for encryption (defaults to AES_256 if empty)
	algorithm string
}

// NewGCPKMSProvider creates a new GCP KMS-based materials manager
func NewGCPKMSProvider(kmsClient GCPKMSClient, options GCPKMSOptions) *GCPKMSProvider {
	// Set default algorithm if not provided
	algorithm := options.Algorithm
	if algorithm == "" {
		algorithm = "AES_256"
	}

	return &GCPKMSProvider{
		kmsClient: kmsClient,
		keyName:   options.KeyName,
		algorithm: algorithm,
	}
}

// GetMaterial generates new encryption materials using GCP KMS
func (g *GCPKMSProvider) GetMaterial(ctx context.Context, cryptoCtx CryptoContext) (*Material, error) {
	// Convert CryptoContext to GCP KMS additional authenticated data
	aad := ContextToBytes(cryptoCtx)

	// Create a data key request
	req := &kmspb.GenerateRandomBytesRequest{
		Location:        extractLocationFromKeyName(g.keyName),
		LengthBytes:     32, // 256 bits
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
	}

	// Generate random bytes for the data key
	randomResp, err := g.kmsClient.GenerateRandomBytes(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}

	plaintextKey := randomResp.Data

	// Encrypt the data key with the KMS key
	encryptReq := &kmspb.EncryptRequest{
		Name:                        g.keyName,
		Plaintext:                   plaintextKey,
		AdditionalAuthenticatedData: aad,
	}

	encryptResp, err := g.kmsClient.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data key: %v", err)
	}

	return &Material{
		PlaintextKey: plaintextKey,
		EncryptedKey: encryptResp.Ciphertext,
	}, nil
}

// DecryptMaterial decrypts the encrypted key using GCP KMS
func (g *GCPKMSProvider) DecryptMaterial(ctx context.Context, cryptoCtx CryptoContext, material *Material) (*Material, error) {
	// Convert CryptoContext to GCP KMS additional authenticated data
	aad := ContextToBytes(cryptoCtx)

	// Create a decrypt request
	req := &kmspb.DecryptRequest{
		Name:                        g.keyName,
		Ciphertext:                  material.EncryptedKey,
		AdditionalAuthenticatedData: aad,
	}

	// Decrypt the data key
	resp, err := g.kmsClient.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %v", err)
	}

	return &Material{
		PlaintextKey: resp.Plaintext,
		EncryptedKey: material.EncryptedKey,
	}, nil
}

// Helper function to extract location from key name
func extractLocationFromKeyName(keyName string) string {
	// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}
	parts := strings.Split(keyName, "/")
	var projectID, location string

	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			projectID = parts[i+1]
		}
		if part == "locations" && i+1 < len(parts) {
			location = parts[i+1]
		}
	}

	if projectID != "" && location != "" {
		return fmt.Sprintf("projects/%s/locations/%s", projectID, location)
	}

	return "projects/default-project/locations/global" // Default location
}
