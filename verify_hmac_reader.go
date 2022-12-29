package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

// VerifyHMACReader is a reader that verifies and strips HMACs from every message
type VerifyHMACReader struct {
	reader  io.Reader        // underlying io.Reader to read from
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length (in bytes) of produced hashes
	key     []byte           // message authentication key
}

// ensure VerifyHMACReader implements io.Reader at compile-time
var _ io.Reader = (*VerifyHMACReader)(nil)

// NewVerifyHMACReader returns a new VerifyHMACReader
func NewVerifyHMACReader(reader io.Reader, key []byte) *VerifyHMACReader {
	r := &VerifyHMACReader{
		reader: reader,
		key:    key,
		hashFn: sha256.New,
	}
	r.hashLen = r.hashFn().Size()
	return r
}

// Read reads data onto the given buffer
func (r *VerifyHMACReader) Read(b []byte) (int, error) {
	// buffer big enough to read hmac and fill b
	buf := make([]byte, r.hashLen+len(b))

	// read at least one byte more than the hash length
	n, err := io.ReadAtLeast(r.reader, buf, r.hashLen+1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("bad message received, too short to have HMAC")
		}
		return 0, fmt.Errorf("failed to read message: %s", err)
	}

	// reduce buffer size to actual data read from reader
	buf = buf[:n]

	// verify and remove HMAC from read data
	msg, err := checkAndStripHMAC(r.hashFn, r.hashLen, r.key, buf)
	if err != nil {
		return 0, fmt.Errorf("failed HMAC verification: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, msg), nil
}
