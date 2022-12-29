package authio

import "io"

// Reader is an authenticated message reader. Note that this
// type serves as an alias to whichever implementation of
// io.Reader is considered the default for this package.
type Reader struct {
	*VerifyHMACReader
}

// ensure Reader implements io.Reader at compile-time
var _ io.Reader = (*Reader)(nil)

// NewReader returns a default Reader implementation
func NewReader(reader io.Reader, key []byte) *Reader {
	return &Reader{NewVerifyHMACReader(reader, key)}
}
