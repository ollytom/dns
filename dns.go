package dns

import (
	"crypto/tls"
	"encoding/binary"
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
	return send(msg, conn)
}

// ExchangeTLS performs a synchronous DNS-over-TLS exchange with addr and returns its
// reply to msg.
func ExchangeTLS(msg dnsmessage.Message, addr string) (dnsmessage.Message, error) {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	return send(msg, conn)
}

func send(msg dnsmessage.Message, conn net.Conn) (dnsmessage.Message, error) {
	packed, err := msg.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var b []byte
	if _, ok := conn.(net.PacketConn); ok {
		b, err = dnsPacketExchange(packed, conn)
		if err != nil {
			return dnsmessage.Message{}, fmt.Errorf("exchange DNS packet: %w", err)
		}
	} else {
		b, err = dnsStreamExchange(packed, conn)
		if err != nil {
			return dnsmessage.Message{}, fmt.Errorf("exchange DNS TCP stream: %w", err)
		}
	}
	var rmsg dnsmessage.Message
	if err := rmsg.Unpack(b); err != nil {
		return dnsmessage.Message{}, fmt.Errorf("parse response: %v", err)
	}
	if rmsg.Header.ID != msg.Header.ID {
		return rmsg, errMismatchedID
	}
	return rmsg, nil
}

func dnsPacketExchange(b []byte, conn net.Conn) ([]byte, error) {
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	buf := make([]byte, 512) // max UDP size per RFC?
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func dnsStreamExchange(b []byte, conn net.Conn) ([]byte, error) {
	// DNS over TCP requires you to prepend the message with a
	// 2-octet length field.
	m := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)
	if _, err := conn.Write(m); err != nil {
		return nil, err
	}

	b = make([]byte, 1280)
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(conn, b[:l])
	if err != nil {
		return nil, fmt.Errorf("read after length: %w", err)
	}
	return b[:n], nil
}
