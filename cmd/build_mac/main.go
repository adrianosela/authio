package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/adrianosela/authio"
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

	result, err := authio.ComputeAndPrependMAC(sha256.New, []byte(key), data)
	if err != nil {
		log.Fatalf("unknown error computing MAC: %s", err)
	}
	fmt.Printf("----MESSAGE-START----|%s|----MESSAGE-END----\n", string(result))
}
