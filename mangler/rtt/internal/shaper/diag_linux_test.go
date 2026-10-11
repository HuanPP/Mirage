//go:build linux

package shaper

import (
	"net"
	"testing"
)

func TestInetDiagEstablishedPort(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	client, e := net.Dial("tcp4", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	samples, e := ClientRTTs(uint16(listener.Addr().(*net.TCPAddr).Port))
	if e != nil {
		t.Fatal(e)
	}
	if len(samples) != 1 {
		t.Fatalf("expected one established inbound socket: %v", samples)
	}
	for _, v := range samples {
		if v <= 0 || v > 1000 {
			t.Fatal("invalid RTT", v)
		}
	}
	t.Logf("inet_diag selected established inbound socket and decoded TCP_INFO RTT: %v", samples)
}
