package dns

import (
	"math/rand"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

var testq = dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}

func resolveBadly(w ResponseWriter, qmsg *dnsmessage.Message) {
		rmsg := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       qmsg.Header.ID + 69,
				Response: false,
				RCode:    dnsmessage.RCodeNameError,
			},
			Questions: qmsg.Questions,
		}
		w.WriteMsg(rmsg)
}

func resolveWrongQuestion(w ResponseWriter, qmsg *dnsmessage.Message) {
	wrongq := dnsmessage.Question{Name: dnsmessage.MustNewName("blabla.example.org."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassCHAOS}
	rmsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       qmsg.Header.ID,
			Response: true,
			RCode:    dnsmessage.RCodeSuccess,
			Authoritative: true,
		},
		Questions: []dnsmessage.Question{wrongq},
	}
	w.WriteMsg(rmsg)
}

func TestBadResolver(t *testing.T) {
	srv := Server{network: "udp", addr: "127.0.0.1", Handler: resolveBadly}
	conn, err := net.ListenPacket("udp", "127.0.0.1:5359")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		t.Fatal(srv.ServePacket(conn))
	}()
	rmsg, err := Ask(testq, "127.0.0.1:5359")
	if err == nil {
		t.Error("wanted error, got nil")
	}
	t.Log(err)
	t.Log("sent:", testq, "received", rmsg)

	srv.Handler = resolveWrongQuestion
	rmsg, err = Ask(testq, "127.0.0.1:5359")
	if err == nil {
		t.Error("wanted error, got nil")
	} else if err != nil {
		t.Log(err)
	}
	t.Log("sent:", testq, "received:", rmsg)
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
