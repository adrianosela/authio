package authio

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"math"
)

// GetMACLength returns the size of MACs produced with a given hash as the basis
func GetMACLenth(h func() hash.Hash) int {
	// MACs are base64 encoded hashes produced by h(). In b64, each
	// character is used to represent 6 bits (log2(64) = 6), So 4
	// chars are used to represent 4 * 6 = 24 bits = 3 bytes. So we
	// need 4*(n/3) chars to represent n bytes. This result is also
	// rounded up to the nearest multiple of 4.
	return int(math.Ceil(float64(h().Size())/3) * 4)
}

// ComputeAndPrependMAC returns a given message with a computed MAC prepended
func ComputeAndPrependMAC(hash func() hash.Hash, key []byte, data []byte) ([]byte, error) {
	// compute MAC for message
	computed := hmac.New(hash, key)
	if _, err := computed.Write(data); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}
	// base64 to avoid special character (e.g. '\n') bytes in hash, without
	// this, certain functions i.e. bufio(authedReader).ReadString('\n')
	// will stop reading at the special character and cause reading to fail.
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// put together message B64(${MAC})${MSG}
	return append([]byte(sum), data...), nil
}

// CheckAndStripMAC verifies a message's MAC matches the message. If the computed
// and received MACs match, returns the original message with the MAC removed.
func CheckAndStripMAC(hash func() hash.Hash, hashLen int, key []byte, data []byte) ([]byte, error) {
	if len(data) < hashLen {
		return nil, fmt.Errorf("buffer too small to have HMAC, got %d, expected >= %d", len(data), hashLen)
	}

	// split data into mac and message
	mac, msg := data[:hashLen], data[hashLen:]

	// compute mac for message
	computed := hmac.New(hash, key)
	if _, err := computed.Write(msg); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}

	// received MAC is base64 to avoid special character (e.g. '\n') bytes in hash
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// compare received vs computed MAC
	if string(mac) != sum {
		return nil, fmt.Errorf("mac did not match sum: mac(%s) vs. sum(%s)", mac, sum)
	}

	// return message
	return msg, nil
}
