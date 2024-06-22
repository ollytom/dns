package main

import (
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"olowe.co/dns"
)

type metrics struct {
	httpOK int
	httpError int
	httpBadReq int
}

func dnsHandler(w http.ResponseWriter, req *http.Request) {
	if v, ok := req.Header["Content-Type"]; ok {
		for _, s := range v {
			if s != dns.MediaType {
				err := fmt.Errorf("unsupported media type %s", s)
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
				counter.httpBadReq++
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
				counter.httpError++
				return
			}
			if length > dns.MaxMsgSize {
				err = fmt.Errorf("content length %d larger than permitted %d", length, dns.MaxMsgSize)
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				counter.httpBadReq++
				return
			}
		}
	}

	if req.Method != http.MethodPost && req.Method != http.MethodGet {
		err := fmt.Errorf("invalid HTTP method %s, must be GET or POST", req.Method)
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusNotImplemented)
		counter.httpBadReq++
		return
	}

	buf := make([]byte, dns.MaxMsgSize)
	var n int
	var err error
	switch req.Method {
	case http.MethodPost:
		n, err = req.Body.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			counter.httpError++
			return
		}
		req.Body.Close()
	case http.MethodGet:
		log.Println("got a GET request but that's not implemented")
		http.Error(w, "in progress!", http.StatusNotImplemented)
		return
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:n]); err != nil {
		log.Println("unpack query:", err)
		http.Error(w, "unpack query: "+err.Error(), http.StatusInternalServerError)
		counter.httpError++
		return
	}

	var resolved dnsmessage.Message
	if conf.usetls {
		resolved, err = dns.ExchangeTLS(msg, conf.forwardaddr)
	} else {
		resolved, err = dns.Exchange(msg, conf.forwardaddr)
	}
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		counter.httpError++
		return
	}
	packed, err := resolved.Pack()
	if err != nil {
		log.Println("pack resolved query:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		counter.httpError++
		return
	}
	w.Header().Add("Content-Type", dns.MediaType)
	if _, err := w.Write(packed); err != nil {
		log.Fatalln(err)
	}
	counter.httpOK++
}

var conf config
var counter metrics

func metricsHandler (w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	w.Write([]byte("# TYPE http_requests_total counter\n"))
	w.Write([]byte(fmt.Sprintf("http_requests_total{code=\"%d\"} %d\n", http.StatusOK, counter.httpOK)))
	w.Write([]byte(fmt.Sprintf("http_requests_total{code=\"%d\"} %d\n", http.StatusInternalServerError, counter.httpError)))
	w.Write([]byte(fmt.Sprintf("http_requests_total{code=\"4xx\"} %d\n", counter.httpBadReq)))
}

func main() {
	var err error
	conf, err = configFromFile("dohproxy.conf")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read configuration:", err)
		os.Exit(1)
	}
	http.HandleFunc("/dns-query", dnsHandler)
	http.HandleFunc("/metrics", metricsHandler)
	log.Fatalln(http.Serve(autocert.NewListener(conf.listenaddr), nil))
}
