package main

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"os"

	"olowe.co/dns"
)

func shouldReject(m *dnsmessage.Message) (bool, dnsmessage.RCode) {
	if !m.Header.RecursionDesired {
		return true, dnsmessage.RCodeRefused
	} else if m.Header.OpCode != dns.OpCodeQUERY {
		return true, dnsmessage.RCodeRefused
	} else if len(m.Questions) != 1 {
		return true, dnsmessage.RCodeFormatError
	} else if m.Questions[0].Type == dnsmessage.TypeALL {
		return true, dnsmessage.RCodeNotImplemented
	} else if m.Questions[0].Class != dnsmessage.ClassINET {
		return true, dnsmessage.RCodeNotImplemented
	}
	return false, dnsmessage.RCodeSuccess
}

func handler(w dns.ResponseWriter, qmsg *dnsmessage.Message) {
	var rmsg dnsmessage.Message
	rmsg.Header.ID = qmsg.Header.ID
	rmsg.Header.Response = true
	rmsg.Header.RecursionAvailable = true
	rmsg.Questions = qmsg.Questions

	if reject, rc := shouldReject(qmsg); reject {
		rmsg.Header.RCode = rc
		w.WriteMsg(rmsg)
		return
	}
	rmsg.RecursionDesired = true

	q := qmsg.Questions[0]
	resolved, err := resolveFromRoot(q)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		rmsg.Header.RCode = dnsmessage.RCodeServerFailure
		w.WriteMsg(rmsg)
		return
	}
	rmsg.Header.RCode = resolved.Header.RCode
	rmsg.Answers = resolved.Answers
	if len(rmsg.Answers) == 0 {
		rmsg.Authorities = resolved.Authorities
		w.WriteMsg(rmsg)
		return
	}
	w.WriteMsg(rmsg)
}

func main() {
	fmt.Fprintln(os.Stderr, dns.ListenAndServe("udp", "", handler))
}
