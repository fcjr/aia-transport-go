# AIA (Authority Information Access) Transport GO [![GoDoc][doc-img]][doc] [![Build Status][ci-img]][ci] [![Coverage Status][cov-img]][cov]

AIA-Transport-Go provides a an http.Transport which ues the AIA (Authority Information Access) certificate extension to resolve incomplete certificate chains during the tls handshake.

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

[doc-img]: https://godoc.org/github.com/fcjr/aia-transport-go?status.svg
[doc]: https://godoc.org/github.com/fcjr/aia-transport-go
[ci-img]: https://travis-ci.com/fcjr/aia-transport-go.svg?branch=master
[ci]: https://travis-ci.com/fcjr/aia-transport-go
[cov-img]: https://codecov.io/gh/fcjr/aia-transport-go/branch/master/graph/badge.svg
[cov]: https://codecov.io/gh/fcjr/aia-transport-go