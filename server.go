package dns

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
)

type Server struct {
	network string
	addr    string
	handler Handler
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

type ResponseWriter interface {
	WriteMsg(dnsmessage.Message) error
}

type Handler func(ResponseWriter, *dnsmessage.Message)

func (srv *Server) ServePacket(conn net.PacketConn) error {
	if srv.handler == nil {
		srv.handler = DefaultHandler
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
			srv.handler(resp, &msg)
		}()
	}
	return nil
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	if srv.handler == nil {
		srv.handler = DefaultHandler
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		msg, _ := receive(conn)
		resp := &response{conn: conn}
		go srv.handler(resp, &msg)
	}
}

func ServePacket(conn net.PacketConn, handler Handler) error {
	srv := &Server{handler: handler}
	return srv.ServePacket(conn)
}

func Serve(l net.Listener, handler Handler) error {
	srv := &Server{handler: handler}
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
	srv := &Server{network: network, addr: addr, handler: handler}
	return srv.ListenAndServe()
}

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
