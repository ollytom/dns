package main

import (
	"net"
	"io"
	"net/http"
	"log"
	"git.sr.ht/~otl/dns"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/dns/dnsmessage"
)

// https://quad9.net
const quad9 string = "9.9.9.9:domain"
const cloudflare string = "1.1.1.1:domain"

func forward(msg dnsmessage.Message) (dnsmessage.Message, error) {
	packed, err := msg.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}

	conn, err := net.Dial("udp", quad9)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()
	if _, err := conn.Write(packed); err != nil {
		return dnsmessage.Message{}, err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	var rmsg dnsmessage.Message
	if err := rmsg.Unpack(buf[:n]); err != nil {
		return dnsmessage.Message{}, err
	}
	return rmsg, nil
}

func dnsHandler(w http.ResponseWriter, req *http.Request) {
	if v, ok := req.Header["Content-Type"]; ok {
		for _, s := range v {
			if s != dns.MediaType {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				 return
			}
		}
	}

	if req.Method != http.MethodPost && req.Method != http.MethodGet {
		http.Error(w, "method must be GET or POST", http.StatusNotImplemented)
		return
	}

	buf := make([]byte, 512)
	switch req.Method {
	case http.MethodPost:
		_, err := req.Body.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Body.Close()
	case http.MethodGet:
		log.Println("got a GET request but that's not implemented")
		http.Error(w, "in progress!", http.StatusNotImplemented)
		return
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(buf); err != nil {
		log.Println("unpack query:", err)
		http.Error(w, "unpack query: "+err.Error(), http.StatusInternalServerError)
	}

	resolved, err := forward(msg)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	packed, err := resolved.Pack()
	if err != nil {
		log.Println("pack resolved query:", err.Error)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.Header().Add("Content-Type", dns.MediaType)
	if _, err := w.Write(packed); err != nil {
		log.Fatalln(err)
	}
}

func main() {
	http.HandleFunc("/dns-query", dnsHandler)
	log.Fatalln(http.Serve(autocert.NewListener("syd.olowe.co"), nil))
}
