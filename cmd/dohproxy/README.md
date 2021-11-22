dohproxy is a basic DNS over HTTPS (DoH) server. It forwards all DNS queries to an upstream resolver via plain DNS or DNS over TLS (DoT), and returns the response to the DoH client.

dohproxy listens on the standard HTTPS port (443) with certificates automatically requested from Let's Encrypt via ACME. DoH requests are made to the standard path `/dns-query`.

The latest version of dohproxy is running at https://syd.olowe.co.
You can test the server by using the `--doh-url` flag of `curl`(1):

	curl --doh-url https://syd.olowe.co/dns-query http://www.example.com

# Build

No make. Just use the standard go tools:

	go build

# Test

Run:

	go test

# Documentation

The [dohproxy documentation](https://man.sr.ht/~otl/dns-docs/dohproxy) contains
details on configuration.
