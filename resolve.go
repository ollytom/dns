package dns

import (
	"fmt"
	"net"
	"strings"
	"golang.org/x/net/dns/dnsmessage"
)


// appends the DNS port to the IP to be used in a dial string.
func ip2dial(ip net.IP) string {
	return net.JoinHostPort(ip.String(), "domain")
}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
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

const rootA = "198.41.0.4"
const rootB = "199.9.14.201"
const rootC = "192.33.4.12"
const rootD = "199.7.91.13"
const rootE = "192.203.230.10"
var roots []net.IP = []net.IP{net.ParseIP(rootA), net.ParseIP(rootB), net.ParseIP(rootC)}

func ResolveFromRoot(q dnsmessage.Question) (dnsmessage.Message, error) {
	return Resolve(q, roots)
}

func Resolve(q dnsmessage.Question, next []net.IP) (dnsmessage.Message, error) {
	var rmsg dnsmessage.Message
	var err error
	for _, ip := range next {
		// Aussie Broadband doesn't support IPv6 yet!
		if isIPv6(ip) {
			continue
		}
		rmsg, err = Ask(q, ip2dial(ip))
		if rmsg.Header.Authoritative {
			return rmsg, err
		} else if rmsg.Header.RCode == dnsmessage.RCodeSuccess && err == nil {
			break
		}
	}
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("resolve %s: %w", q.Name, err)
	}

	// no authoritative answer, so start looking for hints of who to ask next
	if len(rmsg.Additionals) > 0 {
		return Resolve(q, nextServerAddrs(rmsg.Additionals))
	}

	// no hints in additionals, check authorities
	if len(rmsg.Authorities) > 0 {
		for _, a := range rmsg.Authorities {
			switch b := a.Body.(type) {
			case *dnsmessage.NSResource:
				newq := dnsmessage.Question{Name: b.NS, Type: dnsmessage.TypeA, Class: q.Class}
				rmsg, err = ResolveFromRoot(newq)
				if err != nil {
					continue
				}
				if len(rmsg.Answers) > 0 {
					return Resolve(q, nextServerAddrs(rmsg.Answers))
				}
				return Resolve(q, nextServerAddrs(rmsg.Additionals))
			}
		}
	}

	// No real answer, no more servers to ask; return our best guess
	return rmsg, nil
}
