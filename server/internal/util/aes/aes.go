package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type AesService interface {
	Encrypt(s []byte) ([]byte, error)
}

type Aes struct {
	secret []byte
}

func NewAesService(aesSecret []byte) *Aes {
	return &Aes{
		secret: aesSecret,
	}
}

// Encrypt wraps your OAuth token with a random nonce and the AES-GCM tag.
// Format: [nonce][ciphertext][tag]
func (a *Aes) Encrypt(s []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, s, nil), nil
}

// Decrypt extracts the nonce and verifies the tag before returning the token.
func (a *Aes) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split the nonce and the actual encrypted data
	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encryptedData, nil)
}
