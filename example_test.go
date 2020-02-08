package aia_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/fcjr/aia-transport-go"
)

func ExampleNewTransport() {
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

	// Output:
	// 200 OK
}
