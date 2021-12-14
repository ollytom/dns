package main

import (
	"os"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"math/rand"
	"golang.org/x/net/dns/dnsmessage"
	"olowe.co/dns"
)

const rootA = "198.41.0.4"
const rootB = "199.9.14.201"
const rootC = "192.33.4.12"
const rootD = "199.7.91.13"
const rootE = "192.203.230.10"
var roots []net.IP = []net.IP{net.ParseIP(rootA), net.ParseIP(rootB), net.ParseIP(rootC)}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}

// appends the DNS port to the IP to be used in a dial string.
func ip2dial(ip net.IP) string {
	return net.JoinHostPort(ip.String(), "domain")
}

func newID() uint16 {
	return uint16(rand.Intn(65535))
}

func nextServerAddrs(resources []dnsmessage.Resource) []net.IP {
	var next []net.IP
	for _, r := range resources {
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			next = append(next, net.IP(b.A[:]))
		case *dnsmessage.AAAAResource:
			next = append(next, net.IP(b.AAAA[:]))
		}
	}
	return next
}

func resolve(q dnsmessage.Question, next []net.IP) (dnsmessage.Message, error) {
	qmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: newID()},
		Questions: []dnsmessage.Question{q},
	}
	var rmsg dnsmessage.Message
	var err error
	for _, ip := range next {
		// Aussie Broadband doesn't support IPv6 yet!
		if isIPv6(ip) {
			continue
		}
		fmt.Fprintf(os.Stderr, "asking %s about %s\n", ip, q.Name)
		rmsg, err = dns.Exchange(qmsg, ip2dial(ip))
		if rmsg.Header.RCode == dnsmessage.RCodeNameError {
			return rmsg, err
		} else if rmsg.Header.RCode == dnsmessage.RCodeSuccess && err == nil {
			break
		}
	}
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("resolve %s: %w", q.Name, err)
	}
	if len(rmsg.Answers) > 0 {
		return rmsg, nil
	}

	fmt.Fprintf(os.Stderr, "no answer for %s %s, checking additionals\n", q.Name, q.Type)
	if len(rmsg.Additionals) > 0 {
		return resolve(q, nextServerAddrs(rmsg.Additionals))
	}

	fmt.Fprintf(os.Stderr, "no additionals for %s %s, checking authorities\n", q.Name, q.Type)
	if len(rmsg.Authorities) > 0 {
		for _, a := range rmsg.Authorities {
			switch b := a.Body.(type) {
			case *dnsmessage.NSResource:
				newq := dnsmessage.Question{Name: b.NS, Type: dnsmessage.TypeA, Class: q.Class}
				rmsg, err = resolveFromRoot(newq)
				if err != nil {
					continue
				}
				if len(rmsg.Answers) > 0 {
					return resolve(q, nextServerAddrs(rmsg.Answers))
				}
				return resolve(q, nextServerAddrs(rmsg.Additionals))
			}
		}
	}

	return rmsg, nil
	// return rmsg, fmt.Errorf("resolve %s %s: no more servers to query", q.Name, q.Type)
}

func resolveFromRoot(q dnsmessage.Question) (dnsmessage.Message, error) {
	return resolve(q, roots)
}

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
		fmt.Fprintf(os.Stderr, "finished %s %s\n", q.Name, q.Type)
		return
	}
	rmsg.Answers = resolved.Answers
	w.WriteMsg(rmsg)
	cache.Lock()
	cache.m[q] = rmsg.Answers
	fmt.Fprintf(os.Stderr, "added %s %s to cache\n", q.Name, q.Type)
	cache.Unlock()
}

var cache = struct{
	m map[dnsmessage.Question][]dnsmessage.Resource
	sync.RWMutex
}{m: make(map[dnsmessage.Question][]dnsmessage.Resource)}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Fprintln(os.Stderr, dns.ListenAndServe("udp", "", handler))
}
