package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"beryju.io/crtls/internal"
	"github.com/go-kit/kit/log"
	scepdepot "github.com/micromdm/scep/v2/depot"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/spf13/cobra"
)

var (
	serverPort string
	serverHost string
	challenge  string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run a SCEP server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return err
		}

		return serveSCEP(outputDir)
	},
}

func serveSCEP(outputDir string) error {
	logger := log.NewLogfmtLogger(os.Stderr)

	depot := &Depot{outputDir}

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

	var signer scepserver.CSRSignerContext = scepserver.SignCSRAdapter(scepdepot.NewSigner(depot))
	signer = scepserver.StaticChallengeMiddleware(challenge, signer)

	svc, err := scepserver.NewService(caCert, caPrivateKey, signer, scepserver.WithLogger(logger))
	if err != nil {
		return err
	}

	e := scepserver.MakeServerEndpoints(svc)
	h := scepserver.MakeHTTPHandler(e, svc, log.With(logger, "component", "http"))
	fmt.Printf("Starting SCEP on http://%s:%s\n", serverHost, serverPort)

	return http.ListenAndServe(serverHost+":"+serverPort, h)
}

type Depot struct {
	dir string
}

func (d *Depot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	// Load CA private key
	caPrivateKey, err := internal.LoadCAPrivateKey(filepath.Join(d.dir, "ca.key"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to load CA private key")
	}

	// Load CA certificate
	caCert, err := internal.LoadCACertificate(filepath.Join(d.dir, "ca.pem"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to load CA certificate")
	}

	return []*x509.Certificate{caCert}, caPrivateKey, nil
}

func (d *Depot) Serial() (*big.Int, error) {
	return internal.GenerateSerialNumber(), nil
}

func (d *Depot) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	_, err := os.Stat(filepath.Join(d.dir, fmt.Sprintf("cert_%s.pem", cert.Subject.CommonName)))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (d *Depot) Put(name string, crt *x509.Certificate) error {
	// Write certificate to file
	certPath := filepath.Join(d.dir, fmt.Sprintf("cert_%s.pem", crt.Subject.CommonName))
	if err := internal.WriteCertificatePEM(certPath, crt.Raw); err != nil {
		return errors.Wrap(err, "Failed to write certificate")
	}
	return nil
}

func init() {
	Cmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&serverPort, "port", "p", "8000", "Port to serve on")
	serveCmd.Flags().StringVar(&serverHost, "host", "", "Host to serve on")
	serveCmd.Flags().StringVar(&challenge, "challenge", "very-secure-challenge", "SCEP challenge")
}
