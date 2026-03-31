package main

import (
	// "encoding/binary"
	// "fmt"
	// "io"
	"fmt"
	"log"
	"net"
)

// put in another file
type packet struct {
	address net.Addr
	data    []byte
}

func main() {
	port := 9000
	addr := fmt.Sprintf(":%d", port)

	p := packet{}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error creating listener: %s", err)
		return
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Error accepting connection: %s", err)
			continue
		}

		connectionType := conn.LocalAddr().Network()

		if connectionType != "tcp" {
			log.Fatal("connection not tcp")
			continue
		}
		// data := make([]byte, n)
		// binary.Read();
		p.address = conn.RemoteAddr()

		// implement logic for shutting the connection
		// don't allow ^c exits and do same for c version
		// only make it work when doing pkill or systemd
	}

}
