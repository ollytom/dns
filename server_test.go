package dns

import (
	"crypto/rand"
	"io"
	"net"
	"time"
	"testing"
)

func TestServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("udp", "127.0.0.1:51111", nil))
	}()
	time.Sleep(time.Millisecond)
	rmsg, err := Ask(testq, "127.0.0.1:51111")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}

func TestStreamServer(t *testing.T) {
	go func() {
		t.Fatal(ListenAndServe("tcp", "127.0.0.1:51112", nil))
	}()
	time.Sleep(time.Millisecond)
	rmsg, err := AskTCP(testq, "127.0.0.1:51112")
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
	rmsg, err := Ask(testq, "127.0.0.1:domain")
	if err != nil {
		t.Errorf("exchange: %v", err)
	}
	t.Log("response:", rmsg)
}

func TestJunk(t *testing.T) {
	addr := "127.0.0.1:5361"
	go func() {
		t.Fatal(ListenAndServe("tcp", addr, nil))
	}()
	time.Sleep(time.Millisecond)
	for i := 0; i <= 30; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := io.CopyN(conn, rand.Reader, 8192); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkPacketVsStream(b *testing.B) {
	addr := "127.0.0.1:51113"
	var networks = []string{"udp", "tcp"}
	for _, net := range networks {
		go func(){
			b.Fatal(ListenAndServe(net, addr, nil))
		}()
		b.Run(net, func(b *testing.B) {
			for i := 0; i<= b.N; i++ {
				if net == "udp" {
					if rmsg, err := Ask(testq, addr); err != nil {
						b.Log(rmsg)
						b.Fatal(err)
					}
				} else {
					if rmsg, err := AskTCP(testq, addr); err != nil {
						b.Log(rmsg)
						b.Fatal(err)
					}
				}
			}
		})
	}
}
