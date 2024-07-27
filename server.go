package dns

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type Zone struct {
	Name      dnsmessage.Name
	SOA       dnsmessage.SOAResource
	Resources []dnsmessage.Resource
}

// Server contains settings for running a DNS server. An empty Server
// with a nil Handler is a valid configuration.
type Server struct {
	network string
	addr    string
	// Handler is the function which responds to each DNS request
	// received by the server.
	Handler Handler
}

type response struct {
	raddr net.Addr
	pconn net.PacketConn
	conn  net.Conn
}

func (r *response) Write(p []byte) (n int, err error) {
	if r.pconn != nil {
		return r.pconn.WriteTo(p, r.raddr)
	}
	return send(p, r.conn)
}

func (r *response) WriteMsg(msg dnsmessage.Message) error {
	if r.pconn != nil {
		return sendMsgTo(msg, r.pconn, r.raddr)
	}
	return sendMsg(msg, r.conn)
}

// The ResponseWriter interface is used by a Handler to reply to
// DNS requests.
type ResponseWriter interface {
	// Write writes the data to the underlying connection as a DNS response.
	Write(p []byte) (n int, err error)
	// WriteMsg writes the DNS message to the connection.
	WriteMsg(dnsmessage.Message) error
}

// A Handler responds to a DNS message. The function should write a reply
// message to ResponseWriter then return.
type Handler func(ResponseWriter, *dnsmessage.Message)

func (srv *Server) ServePacket(conn net.PacketConn) error {
	if srv.Handler == nil {
		srv.Handler = DefaultHandler
	}
	for {
		buf := make([]byte, 512)
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		go func() {
			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil {
				msg.Header.RCode = dnsmessage.RCodeRefused
				sendMsgTo(msg, conn, raddr)
				return
			}
			resp := &response{raddr: raddr, pconn: conn}
			srv.Handler(resp, &msg)
		}()
	}
	return nil
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	if srv.Handler == nil {
		srv.Handler = DefaultHandler
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		msg, _ := receive(conn)
		resp := &response{conn: conn}
		go srv.Handler(resp, &msg)
	}
}

func ServePacket(conn net.PacketConn, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.ServePacket(conn)
}

func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}

func (srv *Server) ListenAndServe() error {
	if srv.addr == "" {
		srv.addr = ":53"
	}
	switch srv.network {
	case "", "udp", "udp4", "udp6", "unixgram":
		if srv.network == "" {
			srv.network = "udp"
		}
		conn, err := net.ListenPacket(srv.network, srv.addr)
		if err != nil {
			return err
		}
		return srv.ServePacket(conn)
	default:
		l, err := net.Listen(srv.network, srv.addr)
		if err != nil {
			return err
		}
		return srv.Serve(l)
	}
}

func ListenAndServe(network, addr string, handler Handler) error {
	srv := &Server{network: network, addr: addr, Handler: handler}
	return srv.ListenAndServe()
}

// DefaultHandler responds to all DNS messages identically; all messages
// are refused. It is intended as a safe default for a Server which
// does not set a Handler.
var DefaultHandler = Refuse

func respError(w ResponseWriter, msg *dnsmessage.Message, rcode dnsmessage.RCode) {
	w.WriteMsg(dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               msg.Header.ID,
			Response:         true,
			RecursionDesired: msg.Header.RecursionDesired,
			RCode:            rcode,
		},
		Questions: msg.Questions,
	})
}

// FormatError replies to the message with a Format Error message.
func FormatError(w ResponseWriter, msg *dnsmessage.Message) {
	respError(w, msg, dnsmessage.RCodeFormatError)
}

// ServerFailure replies to the message with a Server Failure (SERVFAIL) message.
func ServerFailure(w ResponseWriter, msg *dnsmessage.Message) {
	respError(w, msg, dnsmessage.RCodeServerFailure)
}

// NotImplemented replies to the message with a Not Implemented
// (NOTIMP) message.
func NotImplemented(w ResponseWriter, msg *dnsmessage.Message) {
	respError(w, msg, dnsmessage.RCodeNotImplemented)
}

// Refuse replies to the message with a Refused message.
func Refuse(w ResponseWriter, msg *dnsmessage.Message) {
	respError(w, msg, dnsmessage.RCodeRefused)
}

// NameError replies to the message with a Name error (NXDOMAIN) message.
// The SOA resource and resource header are included in the reply.
// Authoritative servers for the domain in msg should set authoritative to true.
// Others, such as recursive resolvers answers queries, should set this to false.
func NameError(w ResponseWriter, msg *dnsmessage.Message, rh dnsmessage.ResourceHeader, soa dnsmessage.SOAResource, authoritative bool) {
	buf := make([]byte, 2, 512)
	header := dnsmessage.Header{
		ID:               msg.Header.ID,
		Response:         true,
		RecursionDesired: msg.Header.RecursionDesired,
		Authoritative:    authoritative,
		RCode:            dnsmessage.RCodeNameError,
	}
	builder := dnsmessage.NewBuilder(buf, header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		panic(err)
	}
	for _, q := range msg.Questions {
		if err := builder.Question(q); err != nil {
			panic(err)
		}
	}
	if err := builder.StartAuthorities; err != nil {
		panic(err)
	}
	if err := builder.SOAResource(rh, soa); err != nil {
		panic(err)
	}
	buf, err := builder.Finish()
	if err != nil {
		panic(err)
	}
	w.Write(buf[2:])
}

// ExtractIPs extracts any IP addresses from resources. An empty slice is
// returned if there are no addresses.
func ExtractIPs(resources []dnsmessage.Resource) []net.IP {
	var ips []net.IP
	for _, r := range resources {
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, net.IP(b.A[:]))
		case *dnsmessage.AAAAResource:
			ips = append(ips, net.IP(b.AAAA[:]))
		}
	}
	return ips
}
