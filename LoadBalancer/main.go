package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type Loadbalancer struct {
	port            string
	servers         []Server
	roundRobinCount int
}

func newLoadbalancer(p string, servers []Server) *Loadbalancer {
	return &Loadbalancer{
		port:            p,
		roundRobinCount: 0,
		servers:         servers,
	}
}

func (lb *Loadbalancer) getNextAvailableServer() Server {
	server := lb.servers[lb.roundRobinCount%len(lb.servers)]
	for !server.isAlive() {
		lb.roundRobinCount++
		server = lb.servers[lb.roundRobinCount%len(lb.servers)]
	}
	lb.roundRobinCount++
	return server
}

func (lb *Loadbalancer) serveProxy(wr http.ResponseWriter, r *http.Request) {
	tagetServer := lb.getNextAvailableServer()
	fmt.Printf("forwarding requests to address %q\n", tagetServer.Address())
	tagetServer.Serve(wr, r)
}

type Server interface {
	Address() string
	isAlive() bool
	Serve(rw http.ResponseWriter, r *http.Request)
}

func (s *simpleServer) Address() string {
	return s.addr
}

func (s *simpleServer) isAlive() bool {
	return true
}

func (s *simpleServer) Serve(w http.ResponseWriter, r *http.Request) {
	s.proxy.ServeHTTP(w, r)
}

type simpleServer struct {
	addr  string
	proxy httputil.ReverseProxy
}

func newServer(addr string) *simpleServer {
	serverUrl, err := url.Parse(addr)
	if err != nil {
		panic(err)
	}
	return &simpleServer{
		addr:  addr,
		proxy: *httputil.NewSingleHostReverseProxy(serverUrl),
	}
}

func main() {
	servers := []Server{
		newServer("https://www.facebook.com/"),
		newServer("https://snappify.com"),
		newServer("https://www.joshwcomeau.com/gradient-generator"),
	}
	lb := newLoadbalancer("8080", servers)
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		lb.serveProxy(w, r)
	}
	http.HandleFunc("/", handleRedirect)
	fmt.Printf("serving requests at localhost:%s \n", lb.port)
	http.ListenAndServe(":"+lb.port, nil)
}
