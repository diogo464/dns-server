package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"git.d464.sh/diogo464/dns-server/dns"
)

var FlagDebug = flag.Bool("debug", false, "enable debug logs")

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Printf("usage: %v [name]\n", os.Args[0])
		os.Exit(1)
	}

	if *FlagDebug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	rrs, err := dns.Resolve(os.Args[1], dns.TYPE_A)
	if err != nil {
		panic(err)
	}

	for _, rr := range rrs {
		fmt.Println(rr)
	}
}
