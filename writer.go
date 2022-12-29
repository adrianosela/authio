package authio

import "io"

// Writer is an authenticated message writer. Note that this
// type serves as an alias to whichever implementation of
// io.Writer is considered the default for this package.
type Writer struct {
	*AppendHMACWriter
}

// ensure Writer implements io.Writer at compile-time
var _ io.Writer = (*AppendHMACWriter)(nil)

// NewWriter returns a new Writer
func NewWriter(writer io.Writer, key []byte) *Writer {
	return &Writer{NewAppendHMACWriter(writer, key)}
}
