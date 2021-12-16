package dns

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("udp", "127.0.0.1:51111", nil))
	}()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	rmsg, err := Ask(q, "127.0.0.1:51111")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}

func TestStreamServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("tcp", "127.0.0.1:51112", nil))
	}()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	rmsg, err := AskTCP(q, "127.0.0.1:51112")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}

func TestEmptyServer(t *testing.T) {
	srv := &Server{}
	go func() {
		t.Fatal(srv.ListenAndServe())
		t.Log(srv.addr)
	}()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	rmsg, err := Ask(q, "127.0.0.1:domain")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}
