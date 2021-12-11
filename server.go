package dns

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
)

// Server contains settings for running a DNS server.
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

func (r *response) WriteMsg(msg dnsmessage.Message) error {
	if r.pconn != nil {
		return sendPacket(msg, r.pconn, r.raddr)
	}
	return send(msg, r.conn)
}

// The ResponseWriter interface is used by a Handler to reply to
// DNS requests.
type ResponseWriter interface {
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
				sendPacket(msg, conn, raddr)
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
	switch nw := srv.network; nw {
	case "", "udp", "udp4", "udp6", "unixgram":
		if nw == "" {
			nw = "udp"
		}
		conn, err := net.ListenPacket(nw, srv.addr)
		if err != nil {
			return err
		}
		return srv.ServePacket(conn)
	default:
		l, err := net.Listen(nw, srv.addr)
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

// DefaultHandler responds to the DNS message identically. Recursive
// queries are refused and all others are replied to with a "not
// implemented" message. It is intended as a safe default for a Server
// which does not set a Handler.
func DefaultHandler(w ResponseWriter, msg *dnsmessage.Message) {
	var rmsg dnsmessage.Message
	rmsg.Header.ID = msg.Header.ID
	if msg.Header.RecursionDesired {
		rmsg.Header.RCode = dnsmessage.RCodeRefused
		w.WriteMsg(rmsg)
		return
	}
	rmsg.Questions = msg.Questions
	rmsg.Header.RCode = dnsmessage.RCodeNotImplemented
	w.WriteMsg(rmsg)
}
