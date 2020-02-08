package aia

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"time"
)

// NewTransport returns a http.Transport that supports AIA (Authority Information Access) resolution
// for incomplete certificate chains.
func NewTransport() (*http.Transport, error) {

	// Support windows.
	if runtime.GOOS == "windows" {
		return &http.Transport{}, nil
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         addr,
				RootCAs:            rootCAs,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					serverName, _, err := net.SplitHostPort(addr)
					if err != nil {
						return err
					}
					return verifyPeerCerts(rootCAs, serverName, rawCerts)
				},
			})
			if err != nil {
				return conn, err
			}
			return conn, nil
		},
	}, nil
}

func verifyPeerCerts(rootCAs *x509.CertPool, serverName string, rawCerts [][]byte) error {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := certs[0].Verify(opts)
	if err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); ok {
			lastCert := certs[len(certs)-1]
			if len(lastCert.IssuingCertificateURL) >= 1 && lastCert.IssuingCertificateURL[0] != "" {
				resp, err := http.Get(lastCert.IssuingCertificateURL[0])
				if resp != nil {
					defer resp.Body.Close()
				}
				if err != nil {
					return err
				}

				data, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}

				rawCerts = append(rawCerts, data)
				return verifyPeerCerts(rootCAs, serverName, rawCerts)
			}
		}
		return err
	}
	return nil
}
