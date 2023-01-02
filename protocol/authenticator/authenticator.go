package authenticator

import "io"

// MessageAuthenticator represents a message authentication service
type MessageAuthenticator interface {
	GetMessageAuthenticationHeaderLength() int
	GetMessageAuthenticationHeader([]byte) ([]byte, error)
	ReadNext(io.Reader) ([]byte, error)
	AuthenticateMessages([]byte) ([]byte, int, error)
}
