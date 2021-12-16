package main

import (
	"os"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"sync"

	"olowe.co/dns"
)

func handler(w dns.ResponseWriter, qmsg *dnsmessage.Message) {
	var rmsg dnsmessage.Message
	rmsg.Header.ID = qmsg.Header.ID
	rmsg.Header.Response = true
	rmsg.Questions = qmsg.Questions

	if !qmsg.Header.RecursionDesired {
		rmsg.Header.RCode = dnsmessage.RCodeRefused
		w.WriteMsg(rmsg)
		return
	}
	// Reject multiple questions; not even BIND supports it.
	if len(qmsg.Questions) > 1 {
		rmsg.Header.RCode = dnsmessage.RCodeFormatError
		w.WriteMsg(rmsg)
		return
	}

	q := qmsg.Questions[0]
	// CloudFlare rejects these queries too. See RFC 8482
	if q.Type == dnsmessage.TypeALL {
		rmsg.Header.RCode = dnsmessage.RCodeNotImplemented
		w.WriteMsg(rmsg)
		return
	}

	cache.RLock()
	if answers, ok := cache.m[q]; ok {
		rmsg.Answers = answers
		w.WriteMsg(rmsg)
		cache.RUnlock()
		fmt.Fprintf(os.Stderr, "cache served %s %s\n", q.Name, q.Type)
		return
	}
	cache.RUnlock()

	resolved, err := dns.ResolveFromRoot(q)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		rmsg.Header.RCode = dnsmessage.RCodeServerFailure
		w.WriteMsg(rmsg)
		return
	}
	rmsg.Header.RCode = resolved.Header.RCode
	rmsg.Answers = resolved.Answers
	cache.Lock()
	cache.m[q] = rmsg.Answers
	fmt.Fprintf(os.Stderr, "cached %s %s\n", q.Name, q.Type)
	cache.Unlock()
	if len(rmsg.Answers) == 0 {
		rmsg.Authorities = resolved.Authorities
		w.WriteMsg(rmsg)
		return
	}
	rmsg.Answers = resolved.Answers
	w.WriteMsg(rmsg)
}

var cache = struct{
	m map[dnsmessage.Question][]dnsmessage.Resource
	sync.RWMutex
}{m: make(map[dnsmessage.Question][]dnsmessage.Resource)}

func main() {
	fmt.Fprintln(os.Stderr, dns.ListenAndServe("udp", "", handler))
}
