package authio

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/adrianosela/authio/protocol/authenticator"
)

// VerifyMACWriter is a writer that verifies and strips MACs
// on every message before writing them to the underlying writer.
type VerifyMACWriter struct {
	writer        io.Writer // underlying io.Writer to write to
	authenticator authenticator.MessageAuthenticator
	authHeaderLen int
}

// ensure VerifyMACWriter implements io.Writer at compile-time
var _ io.Writer = (*VerifyMACWriter)(nil)

// NewVerifyMACWriter wraps an io.Writer in an VerifyMACWriter
func NewVerifyMACWriter(writer io.Writer, key []byte) *VerifyMACWriter {
	authenticator := authenticator.NewDefaultMessageAuthenticator(sha256.New, key)
	return &VerifyMACWriter{
		writer:        writer,
		authenticator: authenticator,
		authHeaderLen: authenticator.GetMessageAuthenticationHeaderLength(),
	}
}

// Write writes the contents of a buffer to a writer (with MAC excluded)
func (w *VerifyMACWriter) Write(b []byte) (int, error) {
	msg, subMsgCount, err := w.authenticator.AuthenticateMessages(b)
	if err != nil {
		return 0, fmt.Errorf("failed message authentication verification: %s", err)
	}
	n, err := w.writer.Write(msg)
	if err != nil {
		return n + (subMsgCount * w.authHeaderLen), fmt.Errorf("failed to write verified message: %s", err)
	}
	return n + (subMsgCount * w.authHeaderLen), nil
}
