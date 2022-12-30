package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

// VerifyMACReader is a reader that verifies and strips MACs from every message
type VerifyMACReader struct {
	reader io.Reader        // underlying io.Reader to read from
	hashFn func() hash.Hash // function that returns the Hash implementation
	macLen int              // length (in bytes) of produced MACs
	key    []byte           // message authentication key
}

// ensure VerifyMACReader implements io.Reader at compile-time
var _ io.Reader = (*VerifyMACReader)(nil)

// NewVerifyMACReader returns a new VerifyMACReader
func NewVerifyMACReader(reader io.Reader, key []byte) *VerifyMACReader {
	r := &VerifyMACReader{
		reader: reader,
		key:    key,
		hashFn: sha256.New,
	}
	r.macLen = GetMACLength(r.hashFn)
	return r
}

// Read reads data onto the given buffer
func (r *VerifyMACReader) Read(b []byte) (int, error) {
	// buffer big enough to read mac and fill b
	buf := make([]byte, r.macLen+len(b))

	// read at least one hash length (empty message)
	n, err := io.ReadAtLeast(r.reader, buf, r.macLen)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("bad message received, too short to have MAC")
		}
		return 0, fmt.Errorf("failed to read message: %s", err)
	}

	// reduce buffer size to actual data read from reader
	buf = buf[:n]

	// verify and remove MAC from read data
	msg, err := CheckAndStripMAC(r.hashFn, r.macLen, r.key, buf)
	if err != nil {
		return 0, fmt.Errorf("failed MAC verification: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, msg), nil
}
