package dns

import (
	"testing"
)

func TestServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("udp", "127.0.0.1:51111", nil))
	}()
	q, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatalf("create query: %v", err)
	}
	rmsg, err := Exchange(q, "127.0.0.1:51111")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}

func TestStreamServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("tcp", "127.0.0.1:51112", nil))
	}()
	q, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatal("create query:", err)
	}
	rmsg, err := ExchangeTCP(q, "127.0.0.1:51112")
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
	q, err := buildmsg("www.example.com.")
	if err != nil {
		t.Fatal("create query:", err)
	}
	rmsg, err := Exchange(q, "127.0.0.1:domain")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}
