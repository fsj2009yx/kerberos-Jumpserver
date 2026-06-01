package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

func DeriveTargetPasswordKey(nodeID string, kv [8]byte) [32]byte {
	material := make([]byte, 0, len(nodeID)+len(kv)+32)
	material = append(material, "verify-server-ssh-target-password-v1:"...)
	material = append(material, nodeID...)
	material = append(material, ':')
	material = append(material, kv[:]...)
	return sha256.Sum256(material)
}

func encryptTargetPassword(key [32]byte, password string) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(password), nil)
	raw := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

func decryptTargetPassword(key [32]byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("stored password cipher is too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
