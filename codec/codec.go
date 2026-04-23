package codec

import (
	gcpKms "cloud.google.com/go/kms/apiv1"
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	awsKms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/temporal-sa/temporal-cloud-proxy/config"
	"github.com/temporal-sa/temporal-cloud-proxy/crypto"
	"github.com/temporal-sa/temporal-cloud-proxy/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.temporal.io/sdk/converter"
	"os"
	"time"
)

//
//	This could be extended to include codecs of other types (e.g. compression), but
//	is currently focused on encryption specifically.
//

type (
	EncryptionCodecFactory interface {
		NewEncryptionCodec(args EncryptionCodecOptions) (converter.PayloadCodec, error)
	}

	EncryptionCodec interface {
		converter.PayloadCodec
	}

	EncryptionCodecOptions struct {
		LocalEncryptionConfig config.EncryptionConfig
		CodecContext          map[string]string
		MetricsHandler        *metrics.MetricsHandler
	}

	EncryptionCodecConstructor func(args EncryptionCodecOptions) (converter.PayloadCodec, error)

	encryptionCodecFactory struct {
		providers     map[string]EncryptionCodecConstructor
		cachingConfig *crypto.CachingConfig
	}
)

func newCodecFactoryProvider(configProvider config.ConfigProvider) (EncryptionCodecFactory, error) {
	var cachingConfig *crypto.CachingConfig

	providerCacheCfg := configProvider.GetProxyConfig().Encryption.Caching
	if providerCacheCfg.MaxCache > 0 || providerCacheCfg.MaxAge != "" || providerCacheCfg.MaxUsage > 0 {
		cachingConfig = &crypto.CachingConfig{
			MaxCache:        providerCacheCfg.MaxCache,
			MaxMessagesUsed: providerCacheCfg.MaxUsage,
		}
		if providerCacheCfg.MaxAge != "" {
			if duration, err := time.ParseDuration(providerCacheCfg.MaxAge); err == nil {
				cachingConfig.MaxAge = duration
			}
		}
	}

	cf := &encryptionCodecFactory{
		providers:     make(map[string]EncryptionCodecConstructor),
		cachingConfig: cachingConfig,
	}

	cf.providers["aws-kms"] = func(args EncryptionCodecOptions) (converter.PayloadCodec, error) {
		rawKeyId, ok := args.LocalEncryptionConfig.Config["key-id"]
		if !ok {
			return nil, fmt.Errorf("key not found in config")
		}
		keyId, ok := rawKeyId.(string)
		if !ok {
			return nil, fmt.Errorf("key is not a string")
		}

		region := os.Getenv(config.AwsRegionEnvVar)
		if region == "" {
			region = config.DefaultAwsRegion
		}
		sess := session.Must(session.NewSession(&aws.Config{
			Region: aws.String(region),
		}))
		kmsClient := awsKms.New(sess)

		awsMaterialsManager := crypto.NewAWSKMSProvider(kmsClient, crypto.AWSKMSOptions{
			KeyID:   keyId,
			KeySpec: "AES_256",
		})

		args.MetricsHandler.AddAttributes(attribute.String("encryption_key", keyId))

		return NewEncryptionCodecWithCaching(
			awsMaterialsManager,
			args.CodecContext,
			keyId,
			args.MetricsHandler,
			cf.cachingConfig,
		), nil
	}

	cf.providers["gcp-kms"] = func(args EncryptionCodecOptions) (converter.PayloadCodec, error) {
		rawKeyName, ok := args.LocalEncryptionConfig.Config["key-name"]
		if !ok {
			return nil, fmt.Errorf("key not found in config")
		}
		keyName, ok := rawKeyName.(string)
		if !ok {
			return nil, fmt.Errorf("key is not a string")
		}

		region := os.Getenv(config.GcpRegionEnvVar)
		if region == "" {
			region = config.DefaultGcpRegion
		}

		kmsClient, err := gcpKms.NewKeyManagementClient(context.TODO())
		if err != nil {
			return nil, err
		}

		gcpMaterialsManager := crypto.NewGCPKMSProvider(kmsClient, crypto.GCPKMSOptions{
			KeyName:   keyName,
			Algorithm: "AES_256",
		})

		args.MetricsHandler.AddAttributes(attribute.String("encryption_key", keyName))

		return NewEncryptionCodecWithCaching(
			gcpMaterialsManager,
			args.CodecContext,
			keyName,
			args.MetricsHandler,
			cf.cachingConfig,
		), nil
	}

	cf.providers["azure-keyvault"] = func(args EncryptionCodecOptions) (converter.PayloadCodec, error) {
		rawKeyID, ok := args.LocalEncryptionConfig.Config["key-id"]
		if !ok {
			return nil, fmt.Errorf("key not found in config")
		}
		keyID, ok := rawKeyID.(string)
		if !ok {
			return nil, fmt.Errorf("key is not a string")
		}

		vaultURL := os.Getenv(config.AzureVaultURLEnvVar)
		if vaultURL == "" {
			return nil, fmt.Errorf("AZURE_VAULT_URL environment variable is required")
		}

		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure credential: %v", err)
		}

		azClient, err := azkeys.NewClient(vaultURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Key Vault client: %v", err)
		}

		azAdapter := &azureKeysClientAdapter{client: azClient}

		azureMaterialsManager := crypto.NewAzureKeyVaultProvider(azAdapter, crypto.AzureKeyVaultOptions{
			KeyID:     keyID,
			Algorithm: "RSA-OAEP-256",
		})

		args.MetricsHandler.AddAttributes(attribute.String("encryption_key", keyID))

		return NewEncryptionCodecWithCaching(
			azureMaterialsManager,
			args.CodecContext,
			keyID,
			args.MetricsHandler,
			cf.cachingConfig,
		), nil
	}

	return cf, nil
}

// azureKeysClientAdapter adapts azkeys.Client to the crypto.AzureKeyVaultClient interface
type azureKeysClientAdapter struct {
	client *azkeys.Client
}

func (a *azureKeysClientAdapter) WrapKey(ctx context.Context, keyID string, algorithm string, plaintext []byte) ([]byte, error) {
	params := azkeys.KeyOperationParameters{
		Algorithm: toAzKeysAlgorithm(algorithm),
		Value:     plaintext,
	}
	resp, err := a.client.WrapKey(ctx, keyID, "", params, nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func (a *azureKeysClientAdapter) UnwrapKey(ctx context.Context, keyID string, algorithm string, ciphertext []byte) ([]byte, error) {
	params := azkeys.KeyOperationParameters{
		Algorithm: toAzKeysAlgorithm(algorithm),
		Value:     ciphertext,
	}
	resp, err := a.client.UnwrapKey(ctx, keyID, "", params, nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func toAzKeysAlgorithm(algorithm string) *azkeys.EncryptionAlgorithm {
	alg := azkeys.EncryptionAlgorithm(algorithm)
	return &alg
}

func (e *encryptionCodecFactory) NewEncryptionCodec(args EncryptionCodecOptions) (converter.PayloadCodec, error) {
	encryptionCodec, ok := e.providers[args.LocalEncryptionConfig.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported encryption type %s", args.LocalEncryptionConfig.Type)
	}

	return encryptionCodec(args)
}
