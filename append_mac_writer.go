package authio

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// AppendMACWriter is a writer that computes and prepends MACs to every message
type AppendMACWriter struct {
	writer io.Writer        // underlying io.Writer to write to
	hashFn func() hash.Hash // function that returns the Hash implementation
	macLen int              // length (in bytes) of produced MACs
	key    []byte           // message authentication key
}

// ensure AppendMACWriter implements io.Writer at compile-time
var _ io.Writer = (*AppendMACWriter)(nil)

// NewAppendMACWriter wraps an io.Writer in an AppendMACWriter
func NewAppendMACWriter(writer io.Writer, key []byte) *AppendMACWriter {
	w := &AppendMACWriter{
		writer: writer,
		key:    key,
		hashFn: sha256.New,
	}
	w.macLen = GetMACLenth(w.hashFn)
	return w
}

// Write writes the contents of a buffer to a writer (with an included MAC)
func (w *AppendMACWriter) Write(b []byte) (int, error) {
	data, err := ComputeAndPrependMAC(w.hashFn, w.key, b)
	if err != nil {
		return 0, fmt.Errorf("failed to compute MAC for message: %s", err)
	}
	n, err := w.writer.Write(data)
	if err != nil {
		if n >= w.macLen {
			return n - w.macLen, fmt.Errorf("failed to write authenticated message: %s", err)
		}
		// no message bytes were written (only MAC)
		return 0, fmt.Errorf("failed to write authenticated message: %s", err)
	}
	return n - w.macLen, nil
}
