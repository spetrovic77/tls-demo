package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/exp/slices"
)

var (
	flagServer = flag.Bool("server", false, "")

	clientCert, serverCert tls.Certificate
	caCertPool             *x509.CertPool
)

func init() {
	_, fname, _, ok := runtime.Caller(0)
	if !ok {
		panic("no caller info")
	}

	dir := filepath.Join(filepath.Dir(fname), "keys")

	// Load client/server certs.
	cc := filepath.Join(dir, "client.crt")
	ck := filepath.Join(dir, "client.key")
	var err error
	if clientCert, err = tls.LoadX509KeyPair(cc, ck); err != nil {
		panic(err)
	}
	sc := filepath.Join(dir, "server.crt")
	sk := filepath.Join(dir, "server.key")
	if serverCert, err = tls.LoadX509KeyPair(sc, sk); err != nil {
		panic(err)
	}

	// Load CA cert.
	caCert, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		log.Fatal(err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
}

func main() {
	flag.Parse()
	var err error
	if *flagServer {
		err = runServer()
	} else {
		err = runClient()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServer() error {
	config := &tls.Config{
		Certificates:          []tls.Certificate{serverCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caCertPool,
		RootCAs:               caCertPool,
		VerifyPeerCertificate: authorizePeer,
	}
	ln, err := tls.Listen("tcp", ":10000", config)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := handleConnection(conn); err != nil {
				fmt.Fprintln(os.Stderr, "Connection error:", err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		// Read the message.
		msg, err := r.ReadString('\n')
		if err != nil {
			return err
		}

		print(msg)

		if len(msg) == 1 {
			// We're done.
			return nil
		}

		// Remove the first character and reply.
		msg = msg[1:]
		if _, err := conn.Write([]byte(msg)); err != nil {
			return err
		}

		if len(msg) == 1 {
			// We won't be receiving any more messages.
			return nil
		}
	}
}

func authorizePeer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Expect a single certificate/verified chain.
	if len(rawCerts) != 1 {
		return fmt.Errorf("expected a single certificate, got %d", len(rawCerts))
	}
	if len(verifiedChains) != 1 {
		return fmt.Errorf("expected a single verified chain, got %d", len(verifiedChains))
	}
	certs := verifiedChains[0]
	if len(certs) != 2 {
		return fmt.Errorf("expected a verified chain of two certificates, got %d", len(certs))
	}
	if idx := slices.Index(certs[0].DNSNames, "localhost"); idx == -1 {
		return fmt.Errorf("unauthorized peer %v, want localhost", certs[0].DNSNames)
	}
	return nil
}

func runClient() error {
	config := &tls.Config{
		Certificates:          []tls.Certificate{clientCert},
		RootCAs:               caCertPool,
		ClientCAs:             caCertPool,
		VerifyPeerCertificate: authorizePeer,
	}
	config.BuildNameToCertificate()
	dialer := tls.Dialer{
		Config: config,
	}
	conn, err := dialer.Dial("tcp", "localhost:10000")
	if err != nil {
		return err
	}
	if _, err := conn.Write([]byte("hello world\n")); err != nil {
		return err
	}

	return handleConnection(conn)
}
