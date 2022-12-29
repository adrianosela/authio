package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
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
	authedWriter := authio.NewVerifyMACWriter(os.Stdout, []byte(key))
	macLength := authio.GetMACLenth(sha256.New)

	for {
		// read ${REQ_MAC}:${MSG}
		msg, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed to read from connection for client id %d: %s", clientID, err)
			}
			return
		}

		// print client id
		fmt.Printf("[%d] ", clientID)

		// verify ${REQ_MAC}, print ${MSG} to stdout
		_, err = io.WriteString(authedWriter, msg)
		if err != nil {
			log.Printf("failed to write to stdout writer for client id %d: %s", clientID, err)
			return
		}

		// write [${TIMESTAMP}] ${MSG} back
		_, err = io.WriteString(
			authio.NewAppendMACWriter(conn, []byte(key)),
			fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), string([]byte(msg)[macLength:])),
		)
		if err != nil {
			log.Printf("failed to write to writer for client id %d: %s", clientID, err)
			return
		}
	}
}
