package main

import (
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"log"
	"net/http"
	"strconv"

	"git.sr.ht/~otl/dns"
)

// https://quad9.net
const quad9 string = "9.9.9.9:domain"
const cloudflare string = "1.1.1.1:domain"

func dnsHandler(w http.ResponseWriter, req *http.Request) {
	if v, ok := req.Header["Content-Type"]; ok {
		for _, s := range v {
			if s != dns.MediaType {
				err := fmt.Errorf("unsupported media type %s", s)
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
				return
			}
		}
	}

	if v, ok := req.Header["Content-Length"]; ok {
		for _, s := range v {
			length, err := strconv.Atoi(s)
			if err != nil {
				err = fmt.Errorf("parse Content-Length: %v", err)
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if length > dns.MaxMsgSize {
				err = fmt.Errorf("content length %d larger than permitted %d", length, dns.MaxMsgSize)
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
		}
	}

	if req.Method != http.MethodPost && req.Method != http.MethodGet {
		err := fmt.Errorf("invalid HTTP method %s, must be GET or POST", req.Method)
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusNotImplemented)
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

	resolved, err := dns.Exchange(msg, quad9)
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
