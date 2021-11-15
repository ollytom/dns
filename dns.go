package dns

import (
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

func send(msg dnsmessage.Message, conn net.Conn) (dnsmessage.Message, error) {
	packed, err := msg.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}
	if _, err := conn.Write(packed); err != nil {
		return dnsmessage.Message{}, err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var rmsg dnsmessage.Message
	if err := rmsg.Unpack(buf[:n]); err != nil {
		return dnsmessage.Message{}, err
	}
	return rmsg, nil
}
