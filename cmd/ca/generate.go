package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"time"

	"beryju.io/crtls/internal"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	caValidityDays int
	caSubject      string
)

var caGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new Certificate Authority.",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return err
		}

		// Generate private key
		privateKey, err := internal.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "Failed to generate private key")
		}

		subject := pkix.Name{
			CommonName:   caSubject,
			Organization: []string{"crtls"},
		}

		// Create certificate template
		template := &x509.Certificate{
			Subject:      subject,
			Issuer:       subject,
			NotBefore:    time.Now().Add(-24 * time.Hour), // one day before
			NotAfter:     time.Now().Add(time.Duration(caValidityDays) * 24 * time.Hour),
			SerialNumber: internal.GenerateSerialNumber(),
			PublicKey:    &privateKey.PublicKey,

			// Basic Constraints - CA certificate
			IsCA:                  true,
			MaxPathLen:            -1, // No path length constraint
			MaxPathLenZero:        false,
			BasicConstraintsValid: true,

			// Key Usage
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

			// Subject Key Identifier will be automatically generated
		}

		// Create the certificate
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			return errors.Wrap(err, "Failed to create certificate")
		}

		// Write certificate to file
		certPath := filepath.Join(outputDir, "ca.pem")
		if err := internal.WriteCertificatePEM(certPath, certDER); err != nil {
			return errors.Wrap(err, "Failed to write certificate")
		}

		// Write private key to file
		keyPath := filepath.Join(outputDir, "ca.key")
		if err := internal.WritePrivateKeyPEM(keyPath, privateKey); err != nil {
			return errors.Wrap(err, "Failed to write private key")
		}

		fmt.Printf("CA certificate and key generated successfully in %s\n", outputDir)
		return nil

	},
}

func init() {
	Cmd.AddCommand(caGenerateCmd)
	caGenerateCmd.Flags().IntVarP(&caValidityDays, "validity", "v", 3600, "Validity period in days")
	caGenerateCmd.Flags().StringVarP(&caSubject, "subject", "s", "CN=Test CA", "CA subject")
}
