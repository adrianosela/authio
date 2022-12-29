package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/adrianosela/authio"
)

const (
	flagNameProtocol = "protocol"
	flagNameAddress  = "address"
	flagNameKey      = "key"
	defaultProtocol  = "tcp"
	defaultAddress   = "localhost:1234"
	defaultKey       = "mysupersecretstring"
)

var (
	protocol string
	address  string
	key      string
)

func main() {
	// initialize flags
	flag.StringVar(&protocol, flagNameProtocol, defaultProtocol, "listener protocol to use")
	flag.StringVar(&address, flagNameAddress, defaultAddress, "listener address (i.e. HOST:PORT) to use")
	flag.StringVar(&key, flagNameKey, defaultKey, "key to use for message authentication codes")
	flag.Parse()

	// connect to server
	conn, err := net.Dial(protocol, address)
	if err != nil {
		log.Fatalf("could not dial %s to %s", protocol, address)
	}
	defer conn.Close()

	// initialize authenticated reader and writer
	authedReader := authio.NewAppendMACReader(os.Stdin, []byte(key))
	authedWriter := authio.NewVerifyMACWriter(os.Stdout, []byte(key))

	for {
		fmt.Print(">> ")

		// read input from stdin (adds MAC)
		input, err := bufio.NewReader(authedReader).ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", input)
		}

		// write authed input to connection
		connWriter := bufio.NewWriter(conn)
		if _, err = connWriter.WriteString(input); err != nil {
			log.Fatalf("failed to write connection writer: %s", err)
		}
		if err = connWriter.Flush(); err != nil {
			log.Fatalf("failed to flush connection writer: %s", err)
		}

		// read authed response from server
		msg, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Fatalf("failed to read from conn: %s", err)
			}
			return
		}

		// write authed response to stdout (removed MAC)
		writer := bufio.NewWriter(authedWriter)
		if _, err = writer.WriteString(msg); err != nil {
			log.Fatalf("failed to write to authed writer: %s", err)
		}
		if err = writer.Flush(); err != nil {
			log.Fatalf("failed to flush authed writer: %s", err)
		}
	}
}
