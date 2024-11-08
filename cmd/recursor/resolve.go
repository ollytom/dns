package main

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"os"
	"strings"

	"olowe.co/dns"
)

const rootA = "198.41.0.4"
const rootB = "199.9.14.201"
const rootC = "192.33.4.12"
const rootD = "199.7.91.13"
const rootE = "192.203.230.10"

var roots []net.IP = []net.IP{net.ParseIP(rootA), net.ParseIP(rootB), net.ParseIP(rootC)}

// appends the DNS port to the IP to be used in a dial string.
func ip2dial(ip net.IP) string {
	return net.JoinHostPort(ip.String(), "domain")
}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}

func filterRRs(rrs []dnsmessage.Resource, n dnsmessage.Name, t dnsmessage.Type) []dnsmessage.Resource {
	var matches []dnsmessage.Resource
	for _, r := range rrs {
		if r.Header.Name == n && r.Header.Type == t {
			matches = append(matches, r)
		}
	}
	return matches
}

func resolveFromRoot(q dnsmessage.Question) (dnsmessage.Message, error) {
	return resolve(q, roots, 0)
}

func resolve(q dnsmessage.Question, next []net.IP, depth int) (dnsmessage.Message, error) {
	var rmsg dnsmessage.Message
	var err error
	if rrs, ok := lookup(q.Name, q.Type); ok {
		fmt.Fprintln(os.Stderr, "cache served", q.Name, q.Type)
		return dnsmessage.Message{Answers: rrs}, nil
	}
	fmt.Fprintln(os.Stderr, "cache miss", q.Name, q.Type)

	if depth > 12 {
		return dnsmessage.Message{}, fmt.Errorf("query loop")
	}

	for _, ip := range next {
		// Aussie Broadband doesn't support IPv6 yet!
		if isIPv6(ip) {
			continue
		}
		fmt.Fprintf(os.Stderr, "asking %s for %s %s\n", ip, q.Name, q.Type)
		rmsg, err = dns.Ask(q, ip2dial(ip))
		if rmsg.Header.Authoritative {
			fmt.Println("got auth answer")
			insert(q.Name, q.Type, rmsg.Answers)
			fmt.Fprintln(os.Stderr, "cached", q.Name, q.Type)
			return rmsg, err
		} else if rmsg.Header.RCode == dnsmessage.RCodeSuccess && err == nil {
			break
		}
	}
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("resolve %s: %w", q.Name, err)
	}
	fmt.Println("no auth answer")

	// cache resource records from authorities, additionals sections if we
	// don't have them already (i.e. from authoritative answers)
	if len(rmsg.Authorities) > 0 {
		if _, ok := lookup(rmsg.Authorities[0].Header.Name, rmsg.Authorities[0].Header.Type); !ok {
			insert(rmsg.Authorities[0].Header.Name, rmsg.Authorities[0].Header.Type, rmsg.Authorities)
			fmt.Fprintln(os.Stderr, "cached", q.Name, q.Type)
		}
	}
	for _, a := range rmsg.Additionals {
		if _, ok := lookup(a.Header.Name, a.Header.Type); !ok {
			matches := filterRRs(rmsg.Additionals, a.Header.Name, a.Header.Type)
			insert(a.Header.Name, a.Header.Type, matches)
			fmt.Fprintln(os.Stderr, "cached", q.Name, q.Type)
		}
	}

	// get the IP addresses of the nameservers we were told about, then
	// ask the same question to them
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
					return resolve(q, dns.ExtractIPs(rmsg.Answers), depth+1)
				}
				return resolve(q, dns.ExtractIPs(rmsg.Additionals), depth+1)
			default:
				return rmsg, fmt.Errorf("unexpected authority resource type %s", a.Header.Type)
			}
		}
	}

	// return our best guess anyway
	return rmsg, fmt.Errorf("resolve %s: no more nameservers to ask", q.Name)
}
