/*
Package dns provides small DNS client and server implementations built
around the Go project's dnsmessage package. It supports both UDP and
TCP (including TLS).

The package deliberately does not implement all features of the DNS
specifications. Notably EDNS and DNSSEC are unsupported.

TODO(otl): use documentation-reserved IP addresses.
The most basic operation is creating a DNS message, sending it to a
DNS server, then handling the reply using Exchange:

	qmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1},
		Questions: []dnsmessage.Question{
			// ...
		},
	}
	rmsg, err := dns.Exchange(qmsg, "9.9.9.9:domain")
	// ...

Queries to a recursive resolver via DNS over TLS (DoT) can be made with ExchangeTLS:

	name, err := dnsmessage.NewName("www.example.com.")
	if err != nil {
		// handle error
	}
	qmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 69, RecursionDesired: true},
		Questions: []dnsmessage.Question{
			dnsmessage.Question{
				Name: name,
				Type: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	rmsg, err := dns.ExchangeTLS(qmsg, "9.9.9.9:853")

ListenAndServe starts a DNS server listening on the given network and
address. Received messages are managed with the given Handler in a new
goroutine. Handler may be nil, in which case all messages are
gracefully refused.

	log.Fatal(dns.ListenAndServe("udp", ":domain", nil))

Handlers are just functions to which a DNS message from the server is
passed. Responses are written to ResponseWriter.

	func myHandler(w dns.ResponseWriter, qmsg *dnsmessage.Message) {
		var rmsg dnsmessage.Message
		rmsg.Header.ID = qmsg.Header.ID
		if rmsg.Header.RecursionDesired {
			rmsg.Header.RCode = dnsmessage.RCodeRefused
			w.WriteMsg(rmsg)
			return
		}
		// answer questions...
	}

A Server may be created with a custom net.Listener:

	l, err := tls.Listen(network, addr, config)
	srv := &dns.Server{Handler: myHandler}
	log.Fatal(srv.Serve(l))

*/
package dns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

// https://datatracker.ietf.org/doc/html/rfc8484
const MediaType string = "application/dns-message"
const MaxMsgSize int = 65535 // max size of a message in bytes

var errMismatchedID = errors.New("mismatched message id")

// Exchange performs a synchronous, unencrypted UDP DNS exchange with addr and returns its
// reply to msg.
func Exchange(msg dnsmessage.Message, addr string) (dnsmessage.Message, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	return exchange(msg, conn)
}

func ExchangeTCP(msg dnsmessage.Message, addr string) (dnsmessage.Message, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	return exchange(msg, conn)
}

// ExchangeTLS performs a synchronous DNS-over-TLS exchange with addr and returns its
// reply to msg.
func ExchangeTLS(msg dnsmessage.Message, addr string) (dnsmessage.Message, error) {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	return exchange(msg, conn)
}

func exchange(msg dnsmessage.Message, conn net.Conn) (dnsmessage.Message, error) {
	if err := send(msg, conn); err != nil {
		return dnsmessage.Message{}, err
	}
	rmsg, err := receive(conn)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	if rmsg.Header.ID != msg.Header.ID {
		return rmsg, errMismatchedID
	}
	return rmsg, nil
}

func send(msg dnsmessage.Message, conn net.Conn) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	if _, ok := conn.(net.PacketConn); ok {
		if _, err := conn.Write(packed); err != nil {
			return err
		}
		return nil
	}
	// DNS over TCP requires you to prepend the message with a
	// 2-octet length field.
	l := len(packed)
	m := make([]byte, 2+l)
	m[0] = byte(l >> 8)
	m[1] = byte(l)
	copy(m[2:], packed)
	if _, err := conn.Write(m); err != nil {
		return err
	}
	return nil
}

func receive(conn net.Conn) (dnsmessage.Message, error) {
	var buf []byte
	var n int
	var err error
	if _, ok := conn.(net.PacketConn); ok {
		buf = make([]byte, 512)
		n, err = conn.Read(buf)
		if err != nil {
			return dnsmessage.Message{}, err
		}
	} else {
		buf = make([]byte, 1280)
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return dnsmessage.Message{}, fmt.Errorf("read length: %w", err)
		}
		l := int(buf[0])<<8 | int(buf[1])
		if l > len(buf) {
			buf = make([]byte, l)
		}
		n, err = io.ReadFull(conn, buf[:l])
		if err != nil {
			return dnsmessage.Message{}, fmt.Errorf("read after length: %w", err)
		}
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		return dnsmessage.Message{}, err
	}
	return msg, nil
}

func sendPacket(msg dnsmessage.Message, conn net.PacketConn, addr net.Addr) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(packed, addr)
	if err != nil {
		return err
	}
	return nil
}
