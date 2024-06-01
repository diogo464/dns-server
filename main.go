package main

import (
	"fmt"
	"log"
	"net"

	"git.d464.sh/diogo464/dns-server/dns"
)

func main() {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:2053")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	buf := make([]byte, 512)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatalf("failed to read: %v", err)
	}

	msg, err := dns.Decode(buf[:n])
	if err != nil {
		log.Fatalf("failed to decode message: %v", err)
	}
	fmt.Println(msg)

	encoded := dns.Encode(msg)
	if _, err := conn.WriteTo(encoded, addr); err != nil {
		log.Fatalf("failed to write message: %v", err)
	}
}
