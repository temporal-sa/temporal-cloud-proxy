package codec

import (
	"context"
	"fmt"
	"time"

	"temporal-sa/temporal-cloud-proxy/crypto"

	"github.com/aws/aws-sdk-go/service/kms"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
)

const (
	// MetadataEncodingEncrypted is "binary/encrypted"
	MetadataEncodingEncrypted = "binary/encrypted"
	// MetadataEncryptionKeyID is "encryption-key-id"
	MetadataEncryptionKeyID = "encryption-key-id"
	// MetadataEncryptedDataKey is "encrypted-data-key"
	MetadataEncryptedDataKey = "encrypted-data-key"

	// PurposeEncryptionKeyAuth is the purpose for encryption key authentication
	PurposeEncryptionKeyAuth = "encryption-key-auth"
	// PurposePayloadAuth is the purpose for payload authentication
	PurposePayloadAuth = "payload-auth"
)

// Codec implements PayloadCodec using the crypto package's cached material manager.
type Codec struct {
	KeyID        string
	Cipher       *crypto.Cipher
	CodecContext map[string]string
}

// NewEncryptionCodec creates a new encryption codec with the specified key ID, AWS KMS client, and codec context.
func NewEncryptionCodec(kmsClient *kms.KMS, codecContext map[string]string, encryptionKeyID string) converter.PayloadCodec {
	// Create AWS KMS provider
	awsProvider := crypto.NewAWSKMSProvider(kmsClient, crypto.KMSOptions{
		KeyID:   encryptionKeyID,
		KeySpec: "AES_256",
	})

	// Create caching materials manager
	cachingMM, _ := crypto.NewCachingMaterialsManager(
		awsProvider,
		100,           // maxCache
		5*time.Minute, // maxAge
		1000,          // maxMessagesUsed
	)

	// Create cipher with caching materials manager
	cipher := crypto.NewCipher(cachingMM)

	return &Codec{
		KeyID:        encryptionKeyID,
		Cipher:       cipher,
		CodecContext: codecContext,
	}
}

// createCryptoContext creates a crypto context for the given purpose, encryption key ID and codec context
func (e *Codec) createCryptoContext(purpose, encryptionKeyID string, codecContext map[string]string) crypto.CryptoContext {
	cryptoContext := crypto.CryptoContext{
		"purpose":         purpose,
		"encryptionKeyID": encryptionKeyID,
	}

	// Add all codec context values to the crypto context
	for k, v := range codecContext {
		cryptoContext[k] = v
	}

	return cryptoContext
}

// Encode implements converter.PayloadCodec.Encode.
func (e *Codec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		origBytes, err := p.Marshal()
		if err != nil {
			return payloads, err
		}

		keyContext := e.createCryptoContext(PurposeEncryptionKeyAuth, e.KeyID, e.CodecContext)

		// TODO: Reusing key context to auth payload is temporary until we can get additional payload metadata, e.g. workflow ID, run ID, etc.
		// Reference: https://temporaltechnologies.slack.com/archives/C04NYM5D3U6/p1750377050937099
		payloadContext := e.createCryptoContext(PurposePayloadAuth, e.KeyID, e.CodecContext)

		input := &crypto.EncryptInput{
			Plaintext:      origBytes,
			KeyContext:     keyContext,
			PayloadContext: payloadContext,
		}

		ciphertext, encryptedKey, err := e.Cipher.Encrypt(context.Background(), input)
		if err != nil {
			return payloads, err
		}

		result[i] = &commonpb.Payload{
			Metadata: map[string][]byte{
				converter.MetadataEncoding: []byte(MetadataEncodingEncrypted),
				MetadataEncryptionKeyID:    []byte(e.KeyID),
				MetadataEncryptedDataKey:   encryptedKey,
			},
			Data: ciphertext,
		}
	}

	return result, nil
}

// Decode implements converter.PayloadCodec.Decode.
func (e *Codec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		// Only if it's encrypted
		if string(p.Metadata[converter.MetadataEncoding]) != MetadataEncodingEncrypted {
			result[i] = p
			continue
		}

		keyID, ok := p.Metadata[MetadataEncryptionKeyID]
		if !ok {
			return payloads, fmt.Errorf("no encryption key id")
		}

		keyContext := e.createCryptoContext(PurposeEncryptionKeyAuth, string(keyID), e.CodecContext)
		payloadContext := e.createCryptoContext(PurposePayloadAuth, string(keyID), e.CodecContext)

		// Get the encrypted key from metadata
		encryptedKey, ok := p.Metadata[MetadataEncryptedDataKey]
		if !ok {
			return payloads, fmt.Errorf("no encrypted key in payload")
		}

		input := &crypto.DecryptInput{
			Ciphertext:     p.Data,
			EncryptedKey:   encryptedKey,
			KeyContext:     keyContext,
			PayloadContext: payloadContext,
		}

		decrypted, err := e.Cipher.Decrypt(context.Background(), input)
		if err != nil {
			return payloads, err
		}

		result[i] = &commonpb.Payload{}
		err = result[i].Unmarshal(decrypted)
		if err != nil {
			return payloads, err
		}
	}

	return result, nil
}
