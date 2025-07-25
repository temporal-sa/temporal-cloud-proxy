package crypto

type (
	KmsClient interface {
	}

	//KmsProvider interface {
	//	GetMaterial(ctx context.Context, cryptoCtx CryptoContext) (*Material, error)
	//	DecryptMaterial(ctx context.Context, cryptoCtx CryptoContext, material *Material) (*Material, error)
	//}
)

func newCryptoFactoryProvider() {

}

//func Encrypt(plainData []byte, key []byte) ([]byte, error) {
//	c, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	gcm, err := cipher.NewGCM(c)
//	if err != nil {
//		return nil, err
//	}
//
//	nonce := make([]byte, gcm.NonceSize())
//	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
//		return nil, err
//	}
//
//	return gcm.Seal(nonce, nonce, plainData, nil), nil
//}
//
//func Decrypt(encryptedData []byte, key []byte) ([]byte, error) {
//	c, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	gcm, err := cipher.NewGCM(c)
//	if err != nil {
//		return nil, err
//	}
//
//	nonceSize := gcm.NonceSize()
//	if len(encryptedData) < nonceSize {
//		return nil, fmt.Errorf("ciphertext too short: %v", encryptedData)
//	}
//
//	nonce, encryptedData := encryptedData[:nonceSize], encryptedData[nonceSize:]
//	return gcm.Open(nil, nonce, encryptedData, nil)
//}
