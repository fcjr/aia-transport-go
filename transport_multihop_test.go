// +build !windows

package aia_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fcjr/aia-transport-go"
)

func TestTransport_multiHopSemicompleteChainEnd(t *testing.T) {
	certs := map[string][]byte{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if certBytes, ok := certs[path]; ok {
			_, _ = w.Write(certBytes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{ "path" : "%s" }`, path)
	})
	tlsServer := httptest.NewUnstartedServer(handler)
	httpServer := httptest.NewServer(handler)

	ca, _, caPEM, caPrivKey, err := genRootCA()
	if err != nil {
		t.Fatal(err)
	}
	parent := ca
	parentPriv := caPrivKey
	issuer := ""

	intermediates := []*x509.Certificate{}

	for i := 0; i < 5; i++ {
		var certBytes []byte
		parent, certBytes, parentPriv, err = genIntermediate(parent, parentPriv, fmt.Sprintf("AIA Intermediate Cert %d", i), issuer)
		if err != nil {
			t.Fatal(err)
		}
		certs[strconv.Itoa(i)] = certBytes
		issuer = httpServer.URL + "/" + strconv.Itoa(i)

		intermediates = append([]*x509.Certificate{parent}, intermediates...)
	}

	serverCert, serverPrivKey, err := genLeafCertificate(parent, parentPriv, issuer, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := genTLSChain(serverCert, serverPrivKey, intermediates[4])
	if err != nil {
		t.Fatal(err)
	}

	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsServer.StartTLS()

	aiaTr, err := aia.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	aiaTr.TLSClientConfig.RootCAs.AppendCertsFromPEM(caPEM.Bytes())

	client := http.Client{
		Transport: aiaTr,
	}

	testCases := []struct {
		URL         string
		ErrExpected bool
	}{
		{
			URL:         tlsServer.URL + "/multiple-intermediates",
			ErrExpected: false,
		},
	}
	for _, tc := range testCases {
		res, err := client.Get(tc.URL)
		if err != nil && !tc.ErrExpected {
			t.Errorf("%s: err not expected but got: %s", tc.URL, err.Error())
		}
		if err == nil && tc.ErrExpected {
			t.Errorf("%s: expected error but request succeeded!", tc.URL)
		}
		if err == nil && res.Body != nil {
			defer res.Body.Close()
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Log(err)
			} else {
				t.Logf(string(b))
			}
		}
	}
}

func TestTransport_multiHopSemicompleteChainBeginning(t *testing.T) {
	certs := map[string][]byte{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if certBytes, ok := certs[path]; ok {
			_, _ = w.Write(certBytes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{ "path" : "%s" }`, path)
	})
	tlsServer := httptest.NewUnstartedServer(handler)
	httpServer := httptest.NewServer(handler)

	ca, _, caPEM, caPrivKey, err := genRootCA()
	if err != nil {
		t.Fatal(err)
	}
	parent := ca
	parentPriv := caPrivKey
	issuer := ""

	intermediates := []*x509.Certificate{}

	for i := 0; i < 5; i++ {
		var certBytes []byte
		parent, certBytes, parentPriv, err = genIntermediate(parent, parentPriv, fmt.Sprintf("AIA Intermediate Cert %d", i), issuer)
		if err != nil {
			t.Fatal(err)
		}
		certs[strconv.Itoa(i)] = certBytes
		issuer = httpServer.URL + "/" + strconv.Itoa(i)

		intermediates = append([]*x509.Certificate{parent}, intermediates...)
	}

	serverCert, serverPrivKey, err := genLeafCertificate(parent, parentPriv, issuer, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	tlsCert, err := genTLSChain(serverCert, serverPrivKey, intermediates[0], intermediates[1])
	if err != nil {
		t.Fatal(err)
	}

	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsServer.StartTLS()

	aiaTr, err := aia.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	aiaTr.TLSClientConfig.RootCAs.AppendCertsFromPEM(caPEM.Bytes())

	client := http.Client{
		Transport: aiaTr,
	}

	testCases := []struct {
		URL         string
		ErrExpected bool
	}{
		{
			URL:         tlsServer.URL + "/multiple-intermediates",
			ErrExpected: false,
		},
	}
	for _, tc := range testCases {
		res, err := client.Get(tc.URL)
		if err != nil && !tc.ErrExpected {
			t.Errorf("%s: err not expected but got: %s", tc.URL, err.Error())
		}
		if err == nil && tc.ErrExpected {
			t.Errorf("%s: expected error but request succeeded!", tc.URL)
		}
		if err == nil && res.Body != nil {
			defer res.Body.Close()
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Log(err)
			} else {
				t.Logf(string(b))
			}
		}
	}
}

func TestTransport_multiHopIncompleteChain(t *testing.T) {

	certs := map[string][]byte{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if certBytes, ok := certs[path]; ok {
			_, _ = w.Write(certBytes)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{ "path" : "%s" }`, path)
	})
	tlsServer := httptest.NewUnstartedServer(handler)
	httpServer := httptest.NewServer(handler)

	ca, _, caPEM, caPrivKey, err := genRootCA()
	if err != nil {
		t.Fatal(err)
	}
	parent := ca
	parentPriv := caPrivKey
	issuer := ""

	// TODO for later use in more tests
	// intermediates := []*x509.Certificate{}

	for i := 0; i < 5; i++ {
		var certBytes []byte
		parent, certBytes, parentPriv, err = genIntermediate(parent, parentPriv, "AIA Intermediate Cert", issuer)
		if err != nil {
			t.Fatal(err)
		}
		certs[strconv.Itoa(i)] = certBytes
		issuer = httpServer.URL + "/" + strconv.Itoa(i)

		// TODO for later use in more tests
		// intermediates = append([]*x509.Certificate{parent}, intermediates...)
	}

	serverCert, serverPrivKey, err := genLeafCertificate(parent, parentPriv, issuer, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	tlsCert, err := genTLSChain(serverCert, serverPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsServer.StartTLS()

	aiaTr, err := aia.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	aiaTr.TLSClientConfig.RootCAs.AppendCertsFromPEM(caPEM.Bytes())

	client := http.Client{
		Transport: aiaTr,
	}

	testCases := []struct {
		URL         string
		ErrExpected bool
	}{
		{
			URL:         tlsServer.URL + "/multiple-intermediates",
			ErrExpected: false,
		},
	}
	for _, tc := range testCases {
		res, err := client.Get(tc.URL)
		if err != nil && !tc.ErrExpected {
			t.Errorf("%s: err not expected but got: %s", tc.URL, err.Error())
		}
		if err == nil && tc.ErrExpected {
			t.Errorf("%s: expected error but request succeeded!", tc.URL)
		}
		if err == nil && res.Body != nil {
			defer res.Body.Close()
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Log(err)
			} else {
				t.Logf(string(b))
			}
		}
	}

}

func genTLSChain(leafCert *x509.Certificate, leafCertPrivKey *rsa.PrivateKey, intermediates ...*x509.Certificate) (*tls.Certificate, error) {
	leafCertPEM := new(bytes.Buffer)
	err := pem.Encode(leafCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})
	if err != nil {
		return nil, err
	}

	leafCertPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(leafCertPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(leafCertPrivKey),
	})
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(leafCertPEM.Bytes(), leafCertPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}
	for _, intermediate := range intermediates {
		tlsCert.Certificate = append(tlsCert.Certificate, intermediate.Raw)
	}
	return &tlsCert, nil
}

func genLeafCertificate(parent *x509.Certificate, parentPrivKey *rsa.PrivateKey, issuingURL string, ip net.IP) (*x509.Certificate, *rsa.PrivateKey, error) {
	var issuingURLs []string
	if issuingURL != "" {
		issuingURLs = []string{issuingURL}
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"AIA Cert"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"New York"},
			StreetAddress: []string{"Statue Of Liberty"},
			PostalCode:    []string{"00000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		IssuingCertificateURL: issuingURLs,
		IPAddresses:           []net.IP{ip},
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, &certPrivKey.PublicKey, parentPrivKey)
	if err != nil {
		return nil, nil, err
	}

	serverCert, err := x509.ParseCertificate(certBytes)
	return serverCert, certPrivKey, err
}

func genIntermediate(parent *x509.Certificate, parentPrivKey *rsa.PrivateKey, orgName, issuingURL string) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{orgName},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"New York"},
			StreetAddress: []string{"Statue Of Liberty"},
			PostalCode:    []string{"00000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if issuingURL != "" {
		cert.IssuingCertificateURL = []string{issuingURL}
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, &certPrivKey.PublicKey, parentPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	serverCert, err := x509.ParseCertificate(certBytes)
	return serverCert, certBytes, certPrivKey, err
}

func genRootCA() (ca *x509.Certificate, caCert tls.Certificate, caPEM *bytes.Buffer, caPrivKey *rsa.PrivateKey, err error) {
	ca = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"AIA Root Cert"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"New York"},
			StreetAddress: []string{"Statue Of Liberty"},
			PostalCode:    []string{"00000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, tls.Certificate{}, &bytes.Buffer{}, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, tls.Certificate{}, &bytes.Buffer{}, nil, err
	}
	caPEM = new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, tls.Certificate{}, &bytes.Buffer{}, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return nil, tls.Certificate{}, &bytes.Buffer{}, nil, err
	}

	caCert, err = tls.X509KeyPair(caPEM.Bytes(), caPrivKeyPEM.Bytes())
	if err != nil {
		return nil, tls.Certificate{}, &bytes.Buffer{}, nil, err
	}
	return ca, caCert, caPEM, caPrivKey, nil
}
