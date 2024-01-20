package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
}

type simpleDebugListener struct {
	addr   net.Addr
	accept func() (*simpleDebugConnection, io.ReadCloser, io.WriteCloser, error)
}

func (l *simpleDebugListener) Addr() net.Addr { return l.addr }
func (*simpleDebugListener) Close() error     { return nil }

func (l *simpleDebugListener) Accept() (net.Conn, error) {
	conn, reader, writer, err := l.accept()
	if err != nil {
		return nil, err
	}

	return &simpleDebugConnection{
		name:         "server",
		localAddr:    conn.remoteAddr,
		remoteAddr:   conn.localAddr,
		reader:       reader,
		writer:       writer,
		packetWriter: conn.packetWriter,
	}, nil
}

type simpleDebugConnection struct {
	localAddr  net.Addr
	remoteAddr net.Addr

	name   string
	reader io.ReadCloser
	writer io.WriteCloser

	packetWriter PacketWriter
}

func (c *simpleDebugConnection) Close() error {
	c.reader.Close()
	c.writer.Close()
	return nil
}
func (c *simpleDebugConnection) LocalAddr() net.Addr              { return c.localAddr }
func (c *simpleDebugConnection) RemoteAddr() net.Addr             { return c.remoteAddr }
func (*simpleDebugConnection) SetDeadline(t time.Time) error      { return nil }
func (*simpleDebugConnection) SetReadDeadline(t time.Time) error  { return nil }
func (*simpleDebugConnection) SetWriteDeadline(t time.Time) error { return nil }

// Read implements net.Conn.
func (c *simpleDebugConnection) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

// Write implements net.Conn.
func (c *simpleDebugConnection) Write(b []byte) (n int, err error) {
	log.Printf("[%s] write b=%+v", c.name, b)

	err = c.packetWriter.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(b),
		Length:        len(b),
	}, b)
	if err != nil {
		return 0, err
	}

	return c.writer.Write(b)
}

var (
	_ net.Listener = &simpleDebugListener{}
	_ net.Conn     = &simpleDebugConnection{}
)

func makeRandomCert() (*tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Ocean"}},
		NotBefore:             time.Now().Add(time.Hour * 24 * -1),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privKey,
	}, nil
}

func main() {
	log.Printf("start")

	out, err := os.Create("out.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	writer := pcapgo.NewWriter(out)

	err = writer.WriteFileHeader(8192, layers.LinkTypeRaw)
	if err != nil {
		log.Fatal(err)
	}

	listen := &simpleDebugListener{
		accept: func() (*simpleDebugConnection, io.ReadCloser, io.WriteCloser, error) {
			log.Printf("accept")

			readA, writeA := io.Pipe()
			readB, writeB := io.Pipe()

			conn := &simpleDebugConnection{
				name:         "client",
				localAddr:    net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 31231)),
				remoteAddr:   net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 443)),
				reader:       readA,
				writer:       writeB,
				packetWriter: writer,
			}

			client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})

			go func() {
				buf := make([]byte, 1024)

				for {
					_, err := client.Read(buf)
					if err == io.EOF {
						return
					} else if err != nil {
						log.Fatal("read error", err)
					}
				}
			}()

			return conn, readB, writeA, nil
		},
	}

	cert, err := makeRandomCert()
	if err != nil {
		log.Fatal(err)
	}

	tlsListen := tls.NewListener(listen, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})

	log.Printf("accepting")
	conn, err := tlsListen.Accept()
	if err != nil {
		log.Fatal("accept error", err)
	}
	defer conn.Close()

	flag := os.Getenv("FLAG")

	for x := 0; x < 10; x++ {
		log.Printf("writing")
		for i, c := range flag {
			_, err := conn.Write(make([]byte, i))
			if err != nil {
				log.Fatal("write error", err)
			}
			time.Sleep(time.Duration(c) * time.Millisecond)
		}
	}

	log.Printf("finished")
}
