package main

import (
	"flag"
	"log/slog"
	"os"

	"git.d464.sh/diogo464/dns-server/dns"
)

var FlagDebug = flag.Bool("debug", false, "enable debug logs")

func main() {
	flag.Parse()

	// for nameserver, ip := range dns.RootNameServersIpv4 {
	// 	fmt.Printf("%v: %v %v %v %v\n", nameserver, ip[0], ip[1], ip[2], ip[3])
	// }
	//
	// return

	// args := flag.Args()
	// if len(args) != 1 {
	// 	fmt.Printf("usage: %v [name]\n", os.Args[0])
	// 	os.Exit(1)
	// }

	if *FlagDebug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	server, err := dns.NewServer(dns.WithUdpListener("0.0.0.0:2053"))
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := server.Run(); err != nil {
		slog.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}
