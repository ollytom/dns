package main

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"testing"

	"olowe.co/dns"
)

var tquery dnsmessage.Message = dnsmessage.Message{
	Header: dnsmessage.Header{
		ID:               69,
		RecursionDesired: true,
	},
	Questions: []dnsmessage.Question{
		dnsmessage.Question{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		},
	},
}

const testAddr string = "127.0.0.1:5359"
const quad9 string = "9.9.9.9:domain"

func compareMsg(want, got dnsmessage.Message) error {
	if want.Header != got.Header {
		fmt.Errorf("mismatched headers")
	}
	if len(want.Answers) != len(got.Answers) {
		return fmt.Errorf("mismatched answer count")
	}
	if len(want.Answers) == 0 || len(got.Answers) == 0 {
		return fmt.Errorf("unsupported comparison of empty answer messages")
	}
	wantaddr, ok := want.Answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok {
		return fmt.Errorf("unexpected resource type from external resolver")
	}
	gotaddr, ok := got.Answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok {
		return fmt.Errorf("unexpected resource type from our resolver")
	}
	if wantaddr.AAAA != gotaddr.AAAA {
		return fmt.Errorf("wanted %s got %s", wantaddr.AAAA, gotaddr.AAAA)
	}
	return nil
}

func TestMain(m *testing.M) {
	go func() {
		if err := dns.ListenAndServe("udp", testAddr, handler); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()
	os.Exit(m.Run())
}

func TestRecursor(t *testing.T) {
	wanted, err := dns.Exchange(tquery, quad9)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping %s: %v\n", t.Name(), err)
		t.Skip("query internet DNS:", err)
	}
	got, err := dns.Exchange(tquery, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wanted: %+v got %+v", wanted, got)
	if err := compareMsg(wanted, got); err != nil {
		t.Error(err)
	}
	// answer should come from cache
	for i := 0; i <= 1; i++ {
		got, err = dns.Exchange(tquery, testAddr)
		if err = compareMsg(wanted, got); err != nil {
			t.Error("resolve from cache:", err)
		}
	}
	q := tquery
	q.Questions[0].Name = dnsmessage.MustNewName("www.example.net.")
	for i := 0; i <= 1; i++ {
		if _, err = dns.Exchange(q, testAddr); err != nil {
			t.Error("resolve from cache:", err)
		}
	}
	t.Logf("wanted: %+v got %+v", wanted, got)
}

func TestNXDomain(t *testing.T) {
	var wanted, got dnsmessage.Message
	var err error
	wanted, err = dns.Exchange(tquery, quad9)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping %s: %v\n", t.Name(), err)
		t.Skip("query internet DNS:", err)
	}
	q := tquery
	q.Questions[0].Name = dnsmessage.MustNewName("nxdomain.example.com.")
	wanted, err = dns.Exchange(q, quad9)
	if err != nil {
		t.Fatal(err)
	}
	// try twice: first for fresh response, second for cached response
	for i := 0; i <= 1; i++ {
		got, err = dns.Exchange(q, testAddr)
		if err != nil {
			t.Fatal(err)
		}
		if wanted.Header != got.Header {
			t.Error("mismatched headers")
		}
	}
	t.Logf("wanted: %+v got %+v", wanted, got)
}

func TestRefused(t *testing.T) {
	var wanted, got dnsmessage.Message
	var err error
	wanted, err = dns.Exchange(tquery, quad9)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping %s: %v\n", t.Name(), err)
		t.Skip("query internet DNS:", err)
	}
	q := tquery
	q.Questions[0].Name = dnsmessage.MustNewName("kjyq.com.")
	wanted, err = dns.Exchange(q, "8.8.4.4:domain")
	if err != nil {
		t.Fatal(err)
	}
	// try twice: first for fresh response, second for cached response
	for i := 0; i <= 1; i++ {
		got, err = dns.Exchange(q, testAddr)
		if err != nil {
			t.Fatal(err)
		}
		if wanted.Header != got.Header {
			t.Error("mismatched headers")
		}
	}
	t.Logf("wanted: %+v got %+v", wanted, got)
}
