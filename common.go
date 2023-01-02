package authio

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

const sizeLen = 8 // 64 bit unsigned integer

func encodeHeader(hash func() hash.Hash, key []byte, data []byte) ([]byte, error) {
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

	// compute message length including the length bytes, the HMAC, and data
	messageSize := make([]byte, sizeLen)
	binary.BigEndian.PutUint64(messageSize, uint64(len(sum)+len(data)))

	return append(messageSize, []byte(sum)...), nil
}

func decodeHeader(hash func() hash.Hash, hashLen int, key []byte, data []byte) ([]byte, []byte, error) {
	size := binary.BigEndian.Uint64(data[:sizeLen])

	mac := data[sizeLen : sizeLen+hashLen]      // mac is from after the size and before the mac length end
	msg := data[sizeLen+hashLen : sizeLen+size] // msg is from end of mac to end of size (size includes maclen)
	rest := data[sizeLen+size:]                 // rest is everything else

	// compute mac for message
	computed := hmac.New(hash, key)
	if _, err := computed.Write(msg); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, nil, err
	}

	// received MAC is base64 to avoid special character (e.g. '\n') bytes in hash
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// compare received vs computed MAC
	if string(mac) != sum {
		return nil, nil, fmt.Errorf("mac did not match sum: mac(%s) vs. sum(%s)", mac, sum)
	}

	return msg, rest, nil
}

// GetMACLength returns the size of MACs produced with a given hash as the basis
func GetMACLength(h func() hash.Hash) int {
	// MACs are base64 encoded hashes produced by h(). In b64, each
	// character is used to represent 6 bits (log2(64) = 6), So 4
	// chars are used to represent 4 * 6 = 24 bits = 3 bytes. So we
	// need 4*(n/3) chars to represent n bytes. This result is also
	// rounded up to the nearest multiple of 4.
	return int(math.Ceil(float64(h().Size())/3) * 4)
}

// ComputeAndPrependMAC returns a given message with a computed MAC prepended
func ComputeAndPrependMAC(hash func() hash.Hash, key []byte, data []byte) ([]byte, error) {
	header, err := encodeHeader(hash, key, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode message header: %s", err)
	}
	// put together message ${HEADER}${MSG}
	return append(header, data...), nil
}

// CheckAndStripMAC verifies a message's MAC matches the message. If the computed
// and received MACs match, returns the original message with the MAC removed.
func CheckAndStripMAC(hash func() hash.Hash, hashLen int, key []byte, data []byte) ([]byte, int, error) {
	if len(data) < sizeLen+hashLen {
		return nil, 0, fmt.Errorf("buffer too small to have authio header, got %d, expected >= %d", len(data), sizeLen+hashLen)
	}

	rest := data
	msg := []byte{}
	err := (error)(nil)
	subMsgCount := 0

	for len(rest) > 0 {
		var subMsg []byte
		subMsg, rest, err = decodeHeader(hash, hashLen, key, rest)
		if err != nil {
			return nil, subMsgCount, fmt.Errorf("failed decoding header: %s", err)
		}
		msg = append(msg, subMsg...)
		subMsgCount++
	}

	return msg, subMsgCount, nil
}
