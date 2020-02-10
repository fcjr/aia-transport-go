package aia_test

import (
	"net/http"
	"testing"

	"github.com/fcjr/aia-transport-go"
)

func TestTransport(t *testing.T) {
	// test against badssl.com
	testCases := []struct {
		URL         string
		ErrExpected bool
	}{
		{
			URL:         "https://incomplete-chain.badssl.com/",
			ErrExpected: false, // THIS IS THE TRUE TEST
		},
		{
			URL:         "https://expired.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://wrong.host.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://self-signed.host.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://untrusted-root.badssl.com/",
			ErrExpected: true,
		},
		// TODO: go does not check revoked
		// {
		// 	URL:         "https://revoked.badssl.com/",
		// 	ErrExpected: true,
		// },
		// TODO: go does not check for this test
		// {
		// 	URL:         "https://pinning-test.badssl.com/",
		// 	ErrExpected: true,
		// },
		{
			URL:         "https://mitm-software.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://webpack-dev-server.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://preact-cli.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://dsdtestprovider.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://edellroot.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://superfish.badssl.com/",
			ErrExpected: true,
		},
		{
			URL:         "https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/",
			ErrExpected: false,
		},
		{
			URL:         "https://longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com/",
			ErrExpected: false,
		},
		{
			URL:         "https://https-everywhere.badssl.com/",
			ErrExpected: false,
		},
		{
			URL:         "https://preloaded-hsts.badssl.com/",
			ErrExpected: false,
		},
		{
			URL:         "https://tls-v1-2.badssl.com:1012/",
			ErrExpected: false,
		},
	}
	tr, err := aia.NewTransport()
	if err != nil {
		t.Fatalf("failed to build transport")
	}

	client := http.Client{
		Transport: tr,
	}
	for _, tc := range testCases {
		_, err := client.Get(tc.URL)
		if err != nil && !tc.ErrExpected {
			t.Errorf("%s: err not expected but got: %s", tc.URL, err.Error())
		} else if err != nil {
			t.Log(err.Error())
		}
		if err == nil && tc.ErrExpected {
			t.Errorf("%s: expected error but request succeeded!", tc.URL)
		}
	}
}
