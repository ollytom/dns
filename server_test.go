package dns

import (
	"testing"
)

func TestServer(t *testing.T) {
	go func() {
		if err := ListenAndServe("udp", "127.0.0.1:51111", dumbHandler); err != nil {
			t.Fatal(err)
		}
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
		if err := ListenAndServe("tcp", "127.0.0.1:51112", dumbHandler); err != nil {
			t.Fatal(err)
		}
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
