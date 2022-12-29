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

var (
	protocol string
	address  string
	key      string
)

func main() {
	flag.StringVar(&protocol, "protocol", "tcp", "listener protocol to use")
	flag.StringVar(&address, "address", "localhost:1234", "listener address (i.e. HOST:PORT) to use")
	flag.StringVar(&key, "key", "mysupersecretstring", "key to use for message authentication codes")

	conn, err := net.Dial(protocol, address)
	if err != nil {
		log.Fatalf("could not dial %s to %s", protocol, address)
	}
	defer conn.Close()

	authedReader := authio.NewReader(conn, []byte(key))
	authedWriter := authio.NewWriter(conn, []byte(key))

	for {
		fmt.Print(">> ")

		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", input)
		}

		writer := bufio.NewWriter(authedWriter)
		if _, err = writer.WriteString(input); err != nil {
			log.Fatalf("failed to write to writer: %s", err)
		}
		if err = writer.Flush(); err != nil {
			log.Fatalf("failed to flush writer: %s", err)
		}

		msg, err := bufio.NewReader(authedReader).ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
		}

		fmt.Print(msg)
	}
}
