package authio

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// Writer represents an authenticated message writer
type Writer struct {
	writer  io.Writer        // underlying io.Writer to write to
	key     []byte           // message authentication key
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length of resultant HMACs
}

// ensure Writer implements io.Writer at compile-time
var _ io.Writer = (*Writer)(nil)

// NewWriter converts an io.Writer into a Writer
func NewWriter(writer io.Writer, key []byte) *Writer {
	w := &Writer{
		writer: writer,
		key:    key,
		hashFn: sha256.New,
	}
	w.hashLen = w.hashFn().Size()
	return w
}

// Write writes the contents of a buffer to a writer
func (w *Writer) Write(b []byte) (int, error) {
	// compute HMAC for message
	computed := hmac.New(w.hashFn, w.key)
	if n, err := computed.Write(b); err != nil {
		// note: hash.Write() never returns an error as per godoc
		// (https://pkg.go.dev/hash#Hash) but we check it regardless
		return n, err
	}
	sum := computed.Sum(nil)

	// put together data (${HMAC}${MSG})
	data := append(sum, b...)

	// write data to writer
	n, err := w.writer.Write(data)
	if err != nil {
		return n, fmt.Errorf("failed to write signed message: %s", err)
	}
	return n - w.hashLen, nil
}
