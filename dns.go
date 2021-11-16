package dns

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

// https://datatracker.ietf.org/doc/html/rfc8484
const MediaType string = "application/dns-message"
const MaxMsgSize int = 65535 // max size of a message in bytes

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
	if _, ok := conn.(net.PacketConn); ok {
		if _, err = conn.Write(packed); err != nil {
			return dnsmessage.Message{}, err
		}
	} else {
		// DNS over TCP requires you to prepend the message with a
		// 2-octet length field.
		m := make([]byte, 2+len(packed))
		binary.BigEndian.PutUint16(m, uint16(len(packed)))
		copy(m[2:], packed)
		if _, err = conn.Write(m); err != nil {
			return dnsmessage.Message{}, err
		}
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return dnsmessage.Message{}, err
	}
	if n == 0 {
		return dnsmessage.Message{}, fmt.Errorf("empty response")
	}
	var rmsg dnsmessage.Message
	if _, ok := conn.(net.PacketConn); ok {
		if err := rmsg.Unpack(buf[:n]); err != nil {
			return dnsmessage.Message{}, fmt.Errorf("parse response: %v", err)
		}
	} else {
		if err := rmsg.Unpack(buf[2:n]); err != nil {
			return dnsmessage.Message{}, fmt.Errorf("parse response: %v", err)
		}
	}
	return rmsg, nil
}
