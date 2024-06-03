package dns

func applyDefaultServerConfig(config *ServerConfig) {
	config.workers = 8
}

func WithTcpListener(addr string) ServerOption {
	return func(sc *ServerConfig) error {
		sc.tcpAddresses = append(sc.tcpAddresses, addr)
		return nil
	}
}

func WithUdpListener(addr string) ServerOption {
	return func(sc *ServerConfig) error {
		sc.udpAddresses = append(sc.udpAddresses, addr)
		return nil
	}
}

func WithWorkers(n int) ServerOption {
	return func(sc *ServerConfig) error {
		sc.workers = n
		return nil
	}
}
