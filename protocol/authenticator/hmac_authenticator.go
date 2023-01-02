package authenticator

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

// DefaultMessageAuthenticator is an HMAC based MessageAuthenticator
type DefaultMessageAuthenticator struct {
	hashFn    func() hash.Hash
	key       []byte
	headerLen int
}

// ensure MessageAuthenticator implements MessageAuthenticator at compile-time
var _ MessageAuthenticator = (*DefaultMessageAuthenticator)(nil)

const (
	// the message length is transmitted as a binary
	// encoded 64 bit unsigned integer (8 bytes)
	lengthHeaderFieldSize = 8
)

// NewDefaultMessageAuthenticator returns a newly initialized DefaultMessageAuthenticator
func NewDefaultMessageAuthenticator(hashFn func() hash.Hash, key []byte) *DefaultMessageAuthenticator {
	return &DefaultMessageAuthenticator{
		hashFn: hashFn,
		key:    key,

		// header length changes only if the hashFn changes
		headerLen: computeHeaderLengthWithHash(hashFn),
	}
}

// WithHashFn modifies the hash function and hash length on a DefaultMessageAuthenticator and returns it
func (a *DefaultMessageAuthenticator) WithHashFn(hashFn func() hash.Hash) *DefaultMessageAuthenticator {
	a.hashFn = hashFn
	a.headerLen = computeHeaderLengthWithHash(hashFn)
	return a
}

// GetMessageAuthenticationHeaderLength returns the length
// (in bytes) of headers produced by the MessageAuthenticator
func (a *DefaultMessageAuthenticator) GetMessageAuthenticationHeaderLength() int {
	return a.headerLen
}

// GetMessageAuthenticationHeader returns a header produced for the given data
func (a *DefaultMessageAuthenticator) GetMessageAuthenticationHeader(data []byte) ([]byte, error) {
	return encodeHeader(a.hashFn, a.headerLen, a.key, data)
}

// AuthenticateMessages processes one or more messages (each with a header) in a given byte slice.
// It returns the successfully processed raw messages successfully and the number of messages processed.
func (a *DefaultMessageAuthenticator) AuthenticateMessages(data []byte) ([]byte, int, error) {
	processed := []byte{}
	notProcessed := data
	nMessages := 0

	for len(notProcessed) > 0 {
		message, leftOver, err := decodeHeader(a.hashFn, a.headerLen, a.key, notProcessed)
		if err != nil {
			return processed, nMessages, fmt.Errorf("failed decoding header: %s", err)
		}
		processed = append(processed, message...)
		notProcessed = leftOver
		nMessages++
	}

	return processed, nMessages, nil
}

// ReadNext reads and verifies HMAC on a single messages
func (a *DefaultMessageAuthenticator) ReadNext(r io.Reader) ([]byte, error) {
	header := make([]byte, a.headerLen)

	// read header
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read data too short to have valid header")
		}
		return nil, fmt.Errorf("failed to read message header: %s", err)
	}

	mac := header[:a.headerLen-lengthHeaderFieldSize]
	rawSize := header[a.headerLen-lengthHeaderFieldSize:]
	size := binary.BigEndian.Uint64(rawSize)

	msg := make([]byte, size-uint64(a.headerLen)) // we already read the header
	// read msg
	if _, err := io.ReadFull(r, msg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read message too short, does not match message size from header")
		}
		return nil, fmt.Errorf("failed to read message: %s", err)
	}

	// compute mac for message
	computed := hmac.New(a.hashFn, a.key)
	if _, err := computed.Write(append(rawSize, msg...)); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}

	// received MAC is base64 to avoid special character (e.g. '\n') bytes in hash
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// compare received vs computed MAC
	if string(mac) != sum {
		return nil, fmt.Errorf("MAC mismatch: is %s - need %s", sum, mac)
	}

	return msg, nil
}

func computeHeaderLengthWithHash(hashFn func() hash.Hash) int {
	// MACs are base64 encoded hashes produced by h(). In b64, each
	// character is used to represent 6 bits (log2(64) = 6), So 4
	// chars are used to represent 4 * 6 = 24 bits = 3 bytes. So we
	// need 4*(n/3) chars to represent n bytes. This result is also
	// rounded up to the nearest multiple of 4.
	macSize := int(math.Ceil(float64(hashFn().Size())/3) * 4)
	return lengthHeaderFieldSize + macSize
}

func encodeHeader(
	hashFn func() hash.Hash,
	headerLen int,
	key []byte,
	data []byte,
) ([]byte, error) {
	// binary encode message length -- taking into acount header and data.
	encodedMessageLength := make([]byte, lengthHeaderFieldSize)
	binary.BigEndian.PutUint64(encodedMessageLength, uint64(headerLen+len(data)))

	// compute HMAC for message
	computed := hmac.New(hashFn, key)
	if _, err := computed.Write(append(encodedMessageLength, data...)); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, err
	}
	// base64 to avoid special character (e.g. '\n') bytes in hash, without
	// this, certain functions i.e. bufio(authedReader).ReadString('\n')
	// will stop reading at the special character and cause reading to fail.
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// return all header bytes appended
	return append([]byte(sum), encodedMessageLength...), nil
}

func decodeHeader(
	hashFn func() hash.Hash,
	headerLen int,
	key []byte,
	data []byte,
) ([]byte, []byte, error) {
	actualDataLen := len(data)
	if actualDataLen < headerLen {
		return nil, data, fmt.Errorf("data too small to have header, got %d and expected at least %d", actualDataLen, headerLen)
	}

	header := data[:headerLen]
	mac := header[:headerLen-lengthHeaderFieldSize]
	rawSize := header[headerLen-lengthHeaderFieldSize:]

	size := binary.BigEndian.Uint64(rawSize)
	if uint64(actualDataLen) < size {
		return nil, data, fmt.Errorf("data smaller than message length reported in header, got %d and expected at least %d", actualDataLen, size)
	}

	msg := data[headerLen:size] // message starts after header and ends after 'size' bytes
	rest := data[size:]         // rest is everything after 'size' bytes

	// compute mac for message
	computed := hmac.New(hashFn, key)
	if _, err := computed.Write(append(rawSize, msg...)); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return nil, data, err
	}

	// received MAC is base64 to avoid special character (e.g. '\n') bytes in hash
	sum := base64.StdEncoding.EncodeToString(computed.Sum(nil))

	// compare received vs computed MAC
	if string(mac) != sum {
		return nil, data, fmt.Errorf("MAC mismatch: is %s - need %s", sum, mac)
	}

	return msg, rest, nil
}
