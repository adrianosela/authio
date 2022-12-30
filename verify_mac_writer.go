package authio

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// VerifyMACWriter is a writer that verifies and strips MACs
// on every message before writing them to the underlying writer.
//
// WARN: this should never be wrapped in a bufio.BufferedWriter.
//
//	It assumes that each individual Write() includes a MAC.
//	Buffering may result in only part of the message being written
//	in any given Write().
type VerifyMACWriter struct {
	writer io.Writer        // underlying io.Writer to write to
	hashFn func() hash.Hash // function that returns the Hash implementation
	macLen int              // length (in bytes) of produced MACs
	key    []byte           // message authentication key
}

// ensure VerifyMACWriter implements io.Writer at compile-time
var _ io.Writer = (*VerifyMACWriter)(nil)

// NewVerifyMACWriter wraps an io.Writer in an VerifyMACWriter
func NewVerifyMACWriter(writer io.Writer, key []byte) *VerifyMACWriter {
	w := &VerifyMACWriter{
		writer: writer,
		key:    key,
		hashFn: sha256.New,
	}
	w.macLen = GetMACLength(w.hashFn)
	return w
}

// Write writes the contents of a buffer to a writer (with MAC excluded)
func (w *VerifyMACWriter) Write(b []byte) (int, error) {
	msg, err := CheckAndStripMAC(w.hashFn, w.macLen, w.key, b)
	if err != nil {
		return 0, fmt.Errorf("failed MAC verification: %s", err)
	}
	n, err := w.writer.Write(msg)
	if err != nil {
		return n + (sizeLen + w.macLen), fmt.Errorf("failed to write authenticated message: %s", err)
	}
	return n + (sizeLen + w.macLen), nil
}
