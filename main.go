package main

import (
	"flag"
	"log/slog"
	"os"

	"git.d464.sh/diogo464/dns-server/dns"
)

var FlagDebug = flag.Bool("debug", false, "enable debug logs")
var FlagAddress = flag.String("port", "0.0.0.0:2053", "udp listen address")

func main() {
	flag.Parse()

	if *FlagDebug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	server, err := dns.NewServer(dns.WithUdpListener(*FlagAddress))
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := server.Run(); err != nil {
		slog.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}
