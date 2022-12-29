package authio

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
)

func computeAndPrependHMAC(
	hash func() hash.Hash,
	hashLen int,
	key []byte,
	data []byte,
) ([]byte, error) {
	// compute HMAC for message
	computed := hmac.New(hash, key)
	if _, err := computed.Write(data); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}
	sum := computed.Sum(nil)

	// put together message (${HMAC}${MSG})
	return append(sum, data...), nil
}

func checkAndStripHMAC(
	hash func() hash.Hash,
	hashLen int,
	key []byte,
	data []byte,
) ([]byte, error) {
	if len(data) < hashLen {
		return nil, fmt.Errorf("buffer too small to have HMAC, got %d, expected >= %d", len(data), hashLen)
	}

	// split data into hmac and message
	mac, msg := data[:hashLen], data[hashLen:]

	// compute hmac for message
	computed := hmac.New(hash, key)
	if _, err := computed.Write(msg); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}
	sum := computed.Sum(nil)

	// compare received vs computed HMAC
	if string(mac) != string(sum) {
		return nil, fmt.Errorf(
			"mac did not match sum: mac(%s)|sum(%s)",
			base64.StdEncoding.EncodeToString(mac),
			base64.StdEncoding.EncodeToString(sum),
		)
	}

	// return message
	return msg, nil
}
