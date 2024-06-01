package main

import (
	"fmt"
	"log"
	"net"

	"git.d464.sh/diogo464/dns-server/dns"
)

func main() {
	msg := dns.Message{}
	msg.Header.Opcode = dns.OPCODE_QUERY
	msg.Header.QuestionCount = 1
	msg.Header.RecursionDesired = true
	msg.Questions = []dns.Question{
		{
			Name:  "google.com",
			Type:  dns.TYPE_A,
			Class: dns.CLASS_IN,
		},
	}

	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		log.Fatalf("failed to dial dns server: %v", err)
	}

	if _, err := conn.Write(dns.Encode(&msg)); err != nil {
		log.Fatalf("failed to write request: %v", err)
	}

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		log.Fatalf("failed to read response: %v", err)
	}

	resp, err := dns.Decode(buf)
	if err != nil {
		log.Fatalf("failed to decoded response: %v", err)
	}

	fmt.Println(resp)

	// conn, err := net.ListenPacket("udp4", "0.0.0.0:2053")
	// if err != nil {
	// 	log.Fatalf("failed to listen: %v", err)
	// }
	//
	// buf := make([]byte, 512)
	// n, addr, err := conn.ReadFrom(buf)
	// if err != nil {
	// 	log.Fatalf("failed to read: %v", err)
	// }
	//
	// msg, err := dns.Decode(buf[:n])
	// if err != nil {
	// 	log.Fatalf("failed to decode message: %v", err)
	// }
	// fmt.Println(msg)
	//
	// rr := dns.RR{
	// 	Name:  "google.com",
	// 	Type:  dns.TYPE_A,
	// 	Class: dns.CLASS_IN,
	// 	TTL:   60,
	// }
	// rr.EncodeA(dns.RR_A{Addr: [4]byte{127, 0, 0, 1}})
	//
	// msg.Header.AnswerCount = 1
	// msg.Header.Response = true
	// msg.Answers = []dns.RR{rr}
	//
	// encoded := dns.Encode(msg)
	// if _, err := conn.WriteTo(encoded, addr); err != nil {
	// 	log.Fatalf("failed to write message: %v", err)
	// }
}
