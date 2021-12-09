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
