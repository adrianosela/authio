package authio

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Reader represents an authenticated message reader
type Reader struct {
	reader  io.Reader        // underlying io.Reader to read from
	key     []byte           // message authentication key
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length of resultant HMACs
}

// ensure Reader implements io.Reader at compile-time
var _ io.Reader = (*Reader)(nil)

// NewReader returns a new Reader
func NewReader(reader io.Reader, key []byte) *Reader {
	r := &Reader{
		reader: reader,
		key:    key,
		hashFn: sha256.New,
	}
	r.hashLen = r.hashFn().Size()
	return r
}

// Read reads data onto the given buffer
func (r *Reader) Read(b []byte) (int, error) {
	// buffer big enough to read hmac and fill b
	buf := make([]byte, r.hashLen+len(b))

	// read at least one byte more than the hmac length
	n, err := io.ReadAtLeast(r.reader, buf, r.hashLen+1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return n, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return n, fmt.Errorf("bad message received, too short to have HMAC")
		}
		return n, fmt.Errorf("failed to read message: %s", err)
	}

	// split data into hmac and message
	mac, msg := buf[:r.hashLen], buf[r.hashLen:n]

	// compute hmac for message
	computed := hmac.New(r.hashFn, r.key)
	if n, err = computed.Write(msg); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return n, err
	}
	sum := computed.Sum(nil)

	// compare received vs computed HMAC
	if string(mac) != string(computed.Sum(nil)) {
		return 0, fmt.Errorf(
			"mac did not match sum: mac(%s)|sum(%s)",
			base64.StdEncoding.EncodeToString(mac),
			base64.StdEncoding.EncodeToString(sum),
		)
	}

	// copy the message onto the given buffer
	return copy(b, msg), nil
}
