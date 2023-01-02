package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	key := os.Getenv("MAC_PSK")
	if key == "" {
		log.Fatalf("no key in env MAC_PSK")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		if errors.Is(err, io.EOF) {
			log.Fatal("no data in stdin")
		}
		log.Fatalf("unknown error reading from stdin: %s", err)
	}

	computed := hmac.New(sha256.New, []byte(key))
	if _, err := computed.Write(data); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		log.Fatalf("failed to write to hmac: %s", err)
	}
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	fmt.Printf("----B64-HMAC-START----|%s|----B64-HMAC-END----\n", sum)
}
