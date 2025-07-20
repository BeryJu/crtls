package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GenerateSerialNumber() *big.Int {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serialNumber
}
