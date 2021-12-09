package dns

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeDNSConn struct {
	net.Conn
	server fakeDNSServer
	buf    []byte
	tcp    bool
}

type fakeDNSPacketConn struct {
	net.PacketConn
	fakeDNSConn
}

func (f *fakeDNSPacketConn) Close() error {
	return nil
}

type fakeDNSServer struct {
	resolve func(q dnsmessage.Message) (dnsmessage.Message, error)
}

func resolveWell(q dnsmessage.Message) (dnsmessage.Message, error) {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       q.Header.ID,
			Response: true,
			RCode:    dnsmessage.RCodeSuccess,
		},
		Questions: q.Questions,
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Questions[0].Name,
					Type:  q.Questions[0].Type,
					Class: q.Questions[0].Class,
				},
				Body: &dnsmessage.AResource{
					A: [4]byte{0xc0, 0x00, 0x02, 0x01},
				},
			},
		},
	}, nil
}

var errCrashed = errors.New("crashed")

func resolveBadly(q dnsmessage.Message) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, errCrashed
}

func (f fakeDNSConn) Close() error {
	return nil
}

func (f *fakeDNSConn) Write(b []byte) (int, error) {
	time.Sleep(50 * time.Millisecond)
	if len(f.buf) > 0 {
		return 0, fmt.Errorf("connection buffer full, refusing overwrite")
	}
	var qmsg dnsmessage.Message
	if f.tcp {
		if err := qmsg.Unpack(b[2:]); err != nil {
			return len(b), err
		}
	} else {
		if err := qmsg.Unpack(b); err != nil {
			return len(b), err
		}
	}
	rmsg, err := f.server.resolve(qmsg)
	if err != nil {
		return len(b), err
	}
	packed, err := rmsg.Pack()
	if err != nil {
		return len(b), err
	}
	if f.tcp {
		l := len(packed)
		buf := make([]byte, 2+len(packed))
		buf[0] = byte(l >> 8)
		buf[1] = byte(l)
		copy(buf[2:], packed)
		f.buf = buf
		return len(b), nil
	}
	f.buf = packed
	return len(b), err
}

func (f *fakeDNSConn) Read(b []byte) (int, error) {
	if len(f.buf) > 0 {
		n := copy(b, f.buf)
		f.buf = f.buf[n:]
		return n, nil
	}
	return 0, io.EOF
}

func TestGoodConn(t *testing.T) {
	qmsg, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var goodconn fakeDNSConn
	goodconn.server.resolve = resolveWell
	goodconn.tcp = true
	_, err = exchange(qmsg, &goodconn)
	if err != nil {
		t.Error(err)
	}
}

func TestShitConn(t *testing.T) {
	qmsg, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var shitconn fakeDNSConn
	shitconn.server.resolve = resolveBadly
	shitconn.tcp = true
	_, err = exchange(qmsg, &shitconn)
	if !errors.Is(err, errCrashed) {
		t.Errorf("wanted error %v, got %v", errCrashed, err)
	}
}

func TestBadMessage(t *testing.T) {
	q, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var shitconn fakeDNSPacketConn
	shitconn.server.resolve = func(q dnsmessage.Message) (dnsmessage.Message, error) {
		return dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       q.Header.ID + 69,
				Response: false,
				RCode:    dnsmessage.RCodeNameError,
			},
			Questions: q.Questions,
		}, nil
	}
	r, err := exchange(q, &shitconn)
	if !errors.Is(err, errMismatchedID) {
		t.Log(err)
		t.Errorf("should error on receiving mismatched message IDs; sent %d, received %d", q.Header.ID, r.Header.ID)
	}
}

func buildmsg(s string) (dnsmessage.Message, error) {
	name, err := dnsmessage.NewName(s)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var msg dnsmessage.Message
	header := dnsmessage.Header{ID: uint16(rand.Intn(8192)), RecursionDesired: true}
	buf := make([]byte, 2, 512+2)
	b := dnsmessage.NewBuilder(buf, header)
	b.EnableCompression()
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.StartQuestions(); err != nil {
		return msg, err
	}
	if err := b.Question(q); err != nil {
		return msg, err
	}
	packed, err := b.Finish()
	if err != nil {
		return msg, err
	}
	if err := msg.Unpack(packed[2:]); err != nil {
		return msg, err
	}
	return msg, nil
}
