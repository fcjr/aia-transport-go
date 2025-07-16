# AIA (Authority Information Access) Transport Go
[![GoDoc][doc-img]][doc] [![Go Report Card][report-card-img]][report-card] [![Tests][test-img]][test] [![GolangCI][lint-img]][lint]

AIA-Transport-Go provides an http.Transport which uses the AIA (Authority Information Access) X.509 extension to resolve incomplete certificate chains during the tls handshake. See [rfc3280](https://tools.ietf.org/html/rfc3280#section-4.2.2.1) for more details.

## Installation


`go get github.com/fcjr/aia-transport-go`


## Usage

```go
tr, err := aia.NewTransport()
if err != nil {
    log.Fatal(err)
}
client := http.Client{
    Transport: tr,
}
res, err := client.Get("https://incomplete-chain.badssl.com/")
if err != nil {
    log.Fatal(err)
}
fmt.Println(res.Status)
```

## Todos

* [X] Follow single incomplete AIA chain
* [X] Tests
* [X] CI & Code Coverage
* [X] Documentation
* [X] Chain Caching
* [ ] Certificate Caching
* [ ] Follow all possible issuing urls
* [ ] Benchmarks

[doc-img]: https://img.shields.io/static/v1?label=godoc&message=reference&color=blue
[doc]: https://pkg.go.dev/github.com/fcjr/aia-transport-go?tab=doc
[report-card-img]: https://goreportcard.com/badge/github.com/fcjr/aia-transport-go
[report-card]: https://goreportcard.com/report/github.com/fcjr/aia-transport-go
[test-img]: https://github.com/fcjr/aia-transport-go/actions/workflows/test.yml/badge.svg
[test]: https://github.com/fcjr/aia-transport-go/actions?query=workflow%3Atest
[lint-img]: https://github.com/fcjr/aia-transport-go/actions/workflows/lint.yml/badge.svg
[lint]: https://github.com/fcjr/aia-transport-go/actions?query=workflow%3Alint
