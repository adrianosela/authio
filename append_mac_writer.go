package authio

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/adrianosela/authio/protocol/authenticator"
)

// AppendMACWriter is a writer that computes and prepends MACs to every message
type AppendMACWriter struct {
	writer        io.Writer // underlying io.Writer to write to
	authenticator authenticator.MessageAuthenticator
	authHeaderLen int
}

// ensure AppendMACWriter implements io.Writer at compile-time
var _ io.Writer = (*AppendMACWriter)(nil)

// NewAppendMACWriter wraps an io.Writer in an AppendMACWriter
func NewAppendMACWriter(writer io.Writer, key []byte) *AppendMACWriter {
	authenticator := authenticator.NewDefaultMessageAuthenticator(sha256.New, key)
	return &AppendMACWriter{
		writer:        writer,
		authenticator: authenticator,
		authHeaderLen: authenticator.GetMessageAuthenticationHeaderLength(),
	}
}

// Write writes the contents of a buffer to a writer (with an included MAC)
func (w *AppendMACWriter) Write(b []byte) (int, error) {
	header, err := w.authenticator.GetMessageAuthenticationHeader(b)
	if err != nil {
		return 0, fmt.Errorf("failed to compute MAC for message: %s", err)
	}
	n, err := w.writer.Write(append(header, b...))
	if err != nil {
		if n >= w.authHeaderLen {
			return n - w.authHeaderLen, fmt.Errorf("failed to write authenticated message: %s", err)
		}
		// no message bytes were written (only header)
		return 0, fmt.Errorf("failed to write authenticated message: %s", err)
	}
	return n - w.authHeaderLen, nil
}
