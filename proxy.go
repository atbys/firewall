//+build ignore

package main

import (
	"net"
)

type Server struct{}

func (s *Server) Start(listenAddr *net.TCPAddr) error {
	lt, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer lt.Close()

	for {
		conn, err := lt.AcceptTCP()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(c *net.TCPConn) {
	defer c.Close()
	serverAddr := net.ParseIP("10.0.2.16")

	serverConn, err := net.DialTCP("tcp")
}
