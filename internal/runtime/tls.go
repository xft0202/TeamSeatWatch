package runtime

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type ServerTLSConfig struct {
	CAFile                   string
	CertFile                 string
	KeyFile                  string
	AllowedClientCommonNames []string
}

type ClientTLSConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

func LoadServerTLS(config ServerTLSConfig) (*tls.Config, error) {
	if len(config.AllowedClientCommonNames) == 0 {
		return nil, errors.New("at least one allowed client common name is required")
	}
	roots, err := loadCertPool(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load client CA: %w", err)
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	allowed := make(map[string]struct{}, len(config.AllowedClientCommonNames))
	for _, name := range config.AllowedClientCommonNames {
		if name != "" {
			allowed[name] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("allowed client common names cannot be empty")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return errors.New("client certificate chain is not verified")
			}
			if _, ok := allowed[verifiedChains[0][0].Subject.CommonName]; !ok {
				return errors.New("client certificate identity is not allowed")
			}
			return nil
		},
	}, nil
}

func LoadClientTLS(config ClientTLSConfig) (*tls.Config, error) {
	roots, err := loadCertPool(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load server CA: %w", err)
	}
	client := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: config.ServerName,
	}
	if config.CertFile == "" || config.KeyFile == "" {
		if config.CertFile != "" || config.KeyFile != "" {
			return nil, errors.New("client certificate and key must be provided together")
		}
		return client, nil
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	client.Certificates = []tls.Certificate{certificate}
	return client, nil
}

func loadCertPool(filename string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("certificate file contains no certificates")
	}
	return pool, nil
}
