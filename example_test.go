package dns_test

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"olowe.co/dns"
)

// reflectA returns the same A records for every name.
func reflectA(name dnsmessage.Name) (dnsmessage.ResourceHeader, []dnsmessage.AResource) {
	h := dnsmessage.ResourceHeader{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   uint32(3600),
	}
	r1 := dnsmessage.AResource{
		A: [4]byte{192, 0, 2, 1},
	}
	r2 := dnsmessage.AResource{
		A: [4]byte{192, 0, 2, 2},
	}
	return h, []dnsmessage.AResource{r1, r2}
}

func lookup(name dnsmessage.Name, t dnsmessage.Type) (dnsmessage.ResourceHeader, []dnsmessage.AResource) {
	if t != dnsmessage.TypeA {
		// we only have A records
		return dnsmessage.ResourceHeader{}, nil
	}
	return reflectA(name)
}

// authoritativeHandler answers questions for the zone ".test.".
func authoritativeHandler(w dns.ResponseWriter, qmsg *dnsmessage.Message) {
	var rmsg dnsmessage.Message
	rmsg.Header.ID = rmsg.Header.ID
	rmsg.Questions = qmsg.Questions

	// reject empty questions, and any messages with more than 1 question;
	// even BIND doesn't support more than 1 question per message.
	if len(qmsg.Questions) != 1 {
		rmsg.Header.RCode = dnsmessage.RCodeNotImplemented
		w.WriteMsg(rmsg)
		return
	}

	// reject questions for anything other than our our test zone ".test."
	q := qmsg.Questions[0]
	if !strings.HasSuffix(q.Name.String(), ".test.") {
		rmsg.Header.RCode = dnsmessage.RCodeRefused
		w.WriteMsg(rmsg)
		return
	}

	header := dnsmessage.Header{
		ID:            qmsg.Header.ID,
		Response:      true,
		Authoritative: true,
	}
	buf := make([]byte, 2, 512+2)
	builder := dnsmessage.NewBuilder(buf, header)
	builder.EnableCompression()
	rmsg.Header.RCode = dnsmessage.RCodeServerFailure
	if err := builder.StartQuestions(); err != nil {
		w.WriteMsg(rmsg)
		return
	}
	if err := builder.Question(q); err != nil {
		w.WriteMsg(rmsg)
		return
	}
	if err := builder.StartAnswers(); err != nil {
		w.WriteMsg(rmsg)
		return
	}

	resourceHeader, records := lookup(q.Name, q.Type)
	for _, r := range records {
		if err := builder.AResource(resourceHeader, r); err != nil {
			w.WriteMsg(rmsg)
			return
		}
	}
	buf, err := builder.Finish()
	if err != nil {
		w.WriteMsg(rmsg)
		return
	}
	// finished message starts at a 2-byte offset for some reason
	w.Write(buf[2:])
}

func ExampleHandler() {
	qmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(69)},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("www.example.test."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	pipe := pipe{w: os.Stdout}
	authoritativeHandler(pipe, &qmsg)
	// Output: [192.0.2.1 192.0.2.2]
}

type pipe struct {
	w io.Writer
}

func (p pipe) Write(b []byte) (n int, err error) {
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	ips := dns.ExtractIPs(m.Answers)
	fmt.Fprintln(p.w, ips)
	return len(b), nil
}

func (p pipe) WriteMsg(m dnsmessage.Message) error {
	ips := dns.ExtractIPs(m.Answers)
	fmt.Fprintln(p.w, ips)
	return nil
}
