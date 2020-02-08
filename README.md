# AIA (Authority Information Access) Transport GO
[![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Go Report Card][report-card-img]][report-card] [![Coverage Status][cov-img]][cov]

AIA-Transport-Go provides an http.Transport which use the AIA (Authority Information Access) X.509 extension to resolve incomplete certificate chains during the tls handshake. See [rfc3280](https://tools.ietf.org/html/rfc3280#section-4.2.2.1) for more details.

## Installation


`go get github.com/fcjr/aia-transport-go`


## Usage

```go
tr, err := aia.NewTransport()
if err != nil {
    log.Fatal(err)
}
client := http.Client{
    Transport := tr
}
res, err := client.Get("https://incomplete-chain.badssl.com/")
if err != nil {
    log.Fatal(err)
}
fmt.Println(res.Status)
```

## Caveats

This library relies on [x509.SystemCertPool()](https://golang.org/pkg/crypto/x509/#SystemCertPool) to gather the initial system root certificates to validate against.  This function is not implemented on windows, however windows will resolve incomplete certificate chains via AIA automatically so this library simply returns a default http.Transport on windows which should be sufficient.[^1]

[^1]: https://github.com/golang/go/issues/31773#issuecomment-582176197

[doc-img]: https://godoc.org/github.com/fcjr/aia-transport-go?status.svg
[doc]: https://godoc.org/github.com/fcjr/aia-transport-go
[ci-img]: https://travis-ci.org/fcjr/aia-transport-go.svg?branch=master
[ci]: https://travis-ci.org/fcjr/aia-transport-go
[cov-img]: https://codecov.io/gh/fcjr/aia-transport-go/branch/master/graph/badge.svg
[cov]: https://codecov.io/gh/fcjr/aia-transport-go
[report-card-img]: https://goreportcard.com/badge/github.com/fcjr/aia-transport-go
[report-card]: https://goreportcard.com/report/github.com/fcjr/aia-transport-go