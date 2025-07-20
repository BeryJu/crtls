package internal

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

func WriteCertificatePEM(filename string, certDER []byte) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func WritePrivateKeyPEM(filename string, privateKey *rsa.PrivateKey) error {
	keyFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	return pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	})
}

func WritePFX(filename string, privateKey *rsa.PrivateKey, cert *x509.Certificate, password string) error {
	var pfxData []byte
	var err error

	if password != "" {
		pfxData, err = pkcs12.Legacy.Encode(privateKey, cert, nil, password)
	} else {
		pfxData, err = pkcs12.Legacy.Encode(privateKey, cert, nil, "")
	}

	if err != nil {
		return err
	}

	return os.WriteFile(filename, pfxData, 0644)
}
