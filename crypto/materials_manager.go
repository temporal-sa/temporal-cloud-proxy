package crypto

import (
	"context"
	"time"
)

// Material represents cryptographic material with metadata
type Material struct {
	PlaintextKey []byte
	EncryptedKey []byte
	CreatedAt    time.Time
	UsageCount   int
}

// MaterialsManager defines the interface for a materials manager
type MaterialsManager interface {
	GetMaterial(ctx context.Context, cryptoCtx CryptoContext) (*Material, error)
	DecryptMaterial(ctx context.Context, cryptoCtx CryptoContext, material *Material) (*Material, error)
}
