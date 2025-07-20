package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"beryju.io/crtls/internal"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/idna"
)

var certGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new Certificate.",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return err
		}

		subject := args[0]
		subjectAltNames, _ := cmd.Flags().GetStringSlice("subject-alt-names")
		pfxPassword, _ := cmd.Flags().GetString("pfx-password")
		validityDays, _ := cmd.Flags().GetInt("validity-days")

		// Generate private key for the certificate
		privateKey, err := internal.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "Failed to generate private key")
		}

		// Load CA private key
		caPrivateKey, err := internal.LoadCAPrivateKey(filepath.Join(outputDir, "ca.key"))
		if err != nil {
			return errors.Wrap(err, "Failed to load CA private key")
		}

		// Load CA certificate
		caCert, err := internal.LoadCACertificate(filepath.Join(outputDir, "ca.pem"))
		if err != nil {
			return errors.Wrap(err, "Failed to load CA certificate")
		}

		// Prepare Subject Alternative Names
		var sans []string

		// Add the subject as a SAN (convert to ASCII if needed)
		subjectASCII, err := idna.ToASCII(subject)
		if err != nil {
			return errors.Wrap(err, "Failed to convert subject to ASCII")
		}
		sans = append(sans, subjectASCII)

		// Add additional SANs
		for _, san := range subjectAltNames {
			sanASCII, err := idna.ToASCII(san)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("Failed to convert SAN %s to ASCII", san))
			}
			sans = append(sans, sanASCII)
		}

		// Create certificate template
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: subject,
			},
			Issuer:       caCert.Subject,
			NotBefore:    time.Now().Add(-24 * time.Hour), // one day before
			NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
			SerialNumber: internal.GenerateSerialNumber(),
			PublicKey:    &privateKey.PublicKey,

			// Extended Key Usage
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},

			// Subject Alternative Names
			DNSNames: sans,

			// Authority Key Identifier will be set automatically
			// Subject Key Identifier will be set automatically
		}

		// Add IP addresses if any SANs are IP addresses
		for _, san := range sans {
			if ip := net.ParseIP(san); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
				// Remove from DNSNames if it was an IP
				template.DNSNames = internal.RemoveFromSlice(template.DNSNames, san)
			}
		}

		// Create the certificate
		certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caPrivateKey)
		if err != nil {
			return errors.Wrap(err, "Failed to create certificate")
		}

		// Parse the created certificate for PFX generation
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return errors.Wrap(err, "Failed to parse created certificate")
		}

		// Write certificate to file
		certPath := filepath.Join(outputDir, fmt.Sprintf("cert_%s.pem", subject))
		if err := internal.WriteCertificatePEM(certPath, certDER); err != nil {
			return errors.Wrap(err, "Failed to write certificate")
		}

		// Write private key to file
		keyPath := filepath.Join(outputDir, fmt.Sprintf("cert_%s.key", subject))
		if err := internal.WritePrivateKeyPEM(keyPath, privateKey); err != nil {
			return errors.Wrap(err, "Failed to write private key")
		}

		// Create PFX file
		pfxPath := filepath.Join(outputDir, fmt.Sprintf("cert_%s.pfx", subject))
		if err := internal.WritePFX(pfxPath, privateKey, cert, pfxPassword); err != nil {
			return errors.Wrap(err, "Failed to write PFX file")
		}

		fmt.Printf("Certificate generated successfully for %s in %s\n", subject, outputDir)
		return nil
	},
}

func init() {
	Cmd.AddCommand(certGenerateCmd)
	certGenerateCmd.Flags().StringSlice("subject-alt-names", []string{}, "Subject Alternative Names")
	certGenerateCmd.Flags().String("pfx-password", "", "Password for PFX file")
	certGenerateCmd.Flags().IntP("validity-days", "v", 365, "Validity period in days")
}
