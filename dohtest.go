package main

import (
	"net"
	"io"
	"fmt"
	"net/http"
	"log"
//	"golang.org/x/net/dns/dnsmessage"
)

// https://quad9.net
const quad9 string = "9.9.9.9:domain"
const cloudflare string = "1.1.1.1:domain"

func forward(msg []byte) ([]byte, error) {
	fmt.Println("starting to resolve")
	conn, err := net.Dial("udp", cloudflare)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	fmt.Println("dialled upstream ok")
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	fmt.Println("wrote request to upstream ok")
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func dnsHandler(w http.ResponseWriter, req *http.Request) {
	buf := make([]byte, 512)
	switch req.Method {
	case http.MethodPost:
		fmt.Println("got a POST request")
		_, err := req.Body.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println("read request body into buffer")
		req.Body.Close()
	case http.MethodGet:
		log.Println("got a GET request but that's not implemented")
		http.Error(w, "in progress!", http.StatusNotImplemented)
		return
	default:
		http.Error(w, "method must be GET or POST", http.StatusNotImplemented)
		return
	}

	resolved, err := forward(buf)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-type", "application/dns-message")
	if _, err := w.Write(resolved); err != nil {
		log.Fatalln(err)
	}
}

func main() {
	http.HandleFunc("/dns-query", dnsHandler)
	log.Fatalln(http.ListenAndServeTLS("127.0.0.1:8080", "otl.crt", "otl.key", nil))
}
