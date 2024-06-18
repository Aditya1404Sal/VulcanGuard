package loadb

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type Loadbalancer struct {
	Port            string
	Servers         []Server
	RoundRobinCount int
}

func NewLoadbalancer(p string, Servers []Server) *Loadbalancer {
	return &Loadbalancer{
		Port:            p,
		RoundRobinCount: 0,
		Servers:         Servers,
	}
}

func (lb *Loadbalancer) GetNextAvailableServer() Server {
	server := lb.Servers[lb.RoundRobinCount%len(lb.Servers)]
	for !server.IsAlive() {
		lb.RoundRobinCount++
		server = lb.Servers[lb.RoundRobinCount%len(lb.Servers)]
	}
	lb.RoundRobinCount++
	return server
}

func (lb *Loadbalancer) ServeProxy(wr http.ResponseWriter, r *http.Request) {
	tagetServer := lb.GetNextAvailableServer()
	fmt.Printf("forwarding requests to address %q\n", tagetServer.Address())
	tagetServer.Serve(wr, r)
}

type Server interface {
	Address() string
	IsAlive() bool
	Serve(rw http.ResponseWriter, r *http.Request)
}

func (s *SimpleServer) Address() string {
	return s.addr
}

func (s *SimpleServer) IsAlive() bool {
	return true
}

func (s *SimpleServer) Serve(w http.ResponseWriter, r *http.Request) {
	s.proxy.ServeHTTP(w, r)
}

type SimpleServer struct {
	addr  string
	proxy httputil.ReverseProxy
}

func NewServer(addr string) *SimpleServer {
	serverUrl, err := url.Parse(addr)
	if err != nil {
		panic(err)
	}
	return &SimpleServer{
		addr:  addr,
		proxy: *httputil.NewSingleHostReverseProxy(serverUrl),
	}
}
