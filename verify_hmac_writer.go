package authio

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// VerifyHMACWriter is a writer that verifies and strips HMACs
// on every message before writing them to the underlying writer.
//
// WARN: this should never be wrapped in a bufio.BufferedWriter.
//
//	It assumes that each individual Write() includes an HMAC.
//	Buffering may result in only part of the message being written
//	in any given Write().
type VerifyHMACWriter struct {
	writer  io.Writer        // underlying io.Writer to write to
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length (in bytes) of produced hashes
	key     []byte           // message authentication key
}

// ensure VerifyHMACWriter implements io.Writer at compile-time
var _ io.Writer = (*VerifyHMACWriter)(nil)

// NewVerifyHMACWriter wraps an io.Writer in an VerifyHMACWriter
func NewVerifyHMACWriter(writer io.Writer, key []byte) *VerifyHMACWriter {
	w := &VerifyHMACWriter{
		writer: writer,
		key:    key,
		hashFn: sha256.New,
	}
	w.hashLen = w.hashFn().Size()
	return w
}

// Write writes the contents of a buffer to a writer (with HMAC excluded)
func (w *VerifyHMACWriter) Write(b []byte) (int, error) {
	msg, err := checkAndStripHMAC(w.hashFn, w.hashLen, w.key, b)
	if err != nil {
		return 0, fmt.Errorf("failed HMAC verification: %s", err)
	}
	n, err := w.writer.Write(msg)
	if err != nil {
		return n + w.hashLen, fmt.Errorf("failed to write authenticated message: %s", err)
	}
	return n + w.hashLen, nil
}
