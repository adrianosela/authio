package authio

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// AppendHMACWriter is a writer that computes and prepends HMACs to every message
type AppendHMACWriter struct {
	writer  io.Writer        // underlying io.Writer to write to
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length (in bytes) of produced hashes
	key     []byte           // message authentication key
}

// ensure AppendHMACWriter implements io.Writer at compile-time
var _ io.Writer = (*AppendHMACWriter)(nil)

// NewAppendHMACWriter wraps an io.Writer in an AppendHMACWriter
func NewAppendHMACWriter(writer io.Writer, key []byte) *AppendHMACWriter {
	w := &AppendHMACWriter{
		writer: writer,
		key:    key,
		hashFn: sha256.New,
	}
	w.hashLen = w.hashFn().Size()
	return w
}

// Write writes the contents of a buffer to a writer (with an included HMAC)
func (w *AppendHMACWriter) Write(b []byte) (int, error) {
	data, err := computeAndPrependHMAC(w.hashFn, w.hashLen, w.key, b)
	if err != nil {
		return 0, fmt.Errorf("failed to compute HMAC for message: %s", err)
	}
	n, err := w.writer.Write(data)
	if err != nil {
		if n >= w.hashLen {
			return n - w.hashLen, fmt.Errorf("failed to write authenticated message: %s", err)
		}
		// no message bytes were written (only HMAC)
		return 0, fmt.Errorf("failed to write authenticated message: %s", err)
	}
	return n - w.hashLen, nil
}
