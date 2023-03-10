package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

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
	rand.Seed(time.Now().Unix())

	// initialize flags
	flag.StringVar(&protocol, flagNameProtocol, defaultProtocol, "listener protocol to use")
	flag.StringVar(&address, flagNameAddress, defaultAddress, "listener address (i.e. HOST:PORT) to use")
	flag.StringVar(&key, flagNameKey, defaultKey, "key to use for message authentication codes")
	flag.Parse()

	// start server
	l, err := net.Listen(protocol, address)
	if err != nil {
		log.Fatalf("could not start %s listener on %s: %s", protocol, address, err)
	}
	defer l.Close()

	// accept and handle new inbound connections
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalf("could not accept new connection %s listener on %s", protocol, address)
		}
		go handleConn(rand.Intn(1000), c, key)
	}
}

func handleConn(clientID int, conn net.Conn, key string) {
	defer conn.Close()

	// initialize authenticated reader and writer
	authedReader := authio.NewReader(conn, []byte(key))
	authedWriter := authio.NewWriter(conn, []byte(key))

	for {
		// read input from authenticated reader
		data, err := bufio.NewReader(authedReader).ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed to read authed reader for client id %d: %s", clientID, err)
			}
			return
		}

		// write input to stdout
		fmt.Printf("[%d] %s", clientID, data)

		// echo back input with a timestamp on authenticated writer
		writer := bufio.NewWriter(authedWriter)
		_, err = writer.WriteString(fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), data))
		if err != nil {
			log.Printf("failed to write to writer for client id %d: %s", clientID, err)
			return
		}
		if err = writer.Flush(); err != nil {
			log.Printf("failed to flush writer for client id %d: %s", clientID, err)
			return
		}
	}
}
