package authenticator

// MessageAuthenticator represents a message authentication service
type MessageAuthenticator interface {
	GetMessageAuthenticationHeaderLength() int
	GetMessageAuthenticationHeader([]byte) ([]byte, error)
	AuthenticateMessages([]byte) ([]byte, int, error)
}
