package main

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"os"

	"olowe.co/dns"
)

// okQType returns true if t is a query type that we can resolve by
// recursively querying nameservers.
func okQType(t dnsmessage.Type) bool {
	switch t {
	case dnsmessage.TypeA, dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypeSOA, dnsmessage.TypePTR, dnsmessage.TypeMX, dnsmessage.TypeTXT, dnsmessage.TypeAAAA, dnsmessage.TypeSRV, dnsmessage.TypeOPT:
		return true
	}
	return false
}

// rejectHandler is a safeguard to prevent queries we don't want (or support)
// to be recursively resolved. It returns true if the message was rejected.
func rejectHandler(w dns.ResponseWriter, qmsg *dnsmessage.Message) bool {
	if !qmsg.Header.RecursionDesired {
		dns.Refuse(w, qmsg)
		return true
	} else if qmsg.Header.OpCode != dns.OpCodeQUERY {
		dns.Refuse(w, qmsg)
		return true
	} else if len(qmsg.Questions) != 1 {
		dns.FormatError(w, qmsg)
		return true
	}
	q := qmsg.Questions[0]
	if !okQType(q.Type) {
		dns.NotImplemented(w, qmsg)
		return true
	} else if q.Class != dnsmessage.ClassINET {
		dns.NotImplemented(w, qmsg)
		return true
	}
	return false
}

func handler(w dns.ResponseWriter, qmsg *dnsmessage.Message) {
	if rejected := rejectHandler(w, qmsg); rejected {
		return
	}

	var rmsg dnsmessage.Message
	rmsg.Header.ID = qmsg.Header.ID
	rmsg.Header.Response = true
	rmsg.Header.RecursionAvailable = true
	rmsg.Questions = qmsg.Questions
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
