package dns

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
)

type ServerOption func(*ServerConfig) error

type ServerConfig struct {
	workers      int
	tcpAddresses []string
	udpAddresses []string
}

type Server struct {
	ctx       context.Context
	cancel    context.CancelFunc
	config    *ServerConfig
	listeners []io.Closer
	workers   []*worker
}

type messageWithAddr struct {
	message *Message
	addr    net.Addr
}

func NewServer(opts ...ServerOption) (*Server, error) {
	config := &ServerConfig{}
	applyDefaultServerConfig(config)
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		ctx:    ctx,
		cancel: cancel,
		config: config,
	}

	return server, nil
}

func (s *Server) Run() error {
	defer s.Finish()

	if len(s.config.tcpAddresses) == 0 && len(s.config.udpAddresses) == 0 {
		slog.Warn("no listen addresses configured")
	}

	slog.Debug("spawning workers", "workers", s.config.workers)
	authorityCache := NewSharedAuthorityCache()
	resourceCache := NewSharedResourceCache()
	for i := 0; i < s.config.workers; i++ {
		worker := newWorker(authorityCache, resourceCache)
		s.workers = append(s.workers, worker)
		go worker.run()
	}

	for _, tcpAddr := range s.config.tcpAddresses {
		slog.Debug("starting tcp listener", "address", tcpAddr)
		listener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, listener)
		go s.receiverTcp(listener)
	}

	for _, udpAddr := range s.config.udpAddresses {
		slog.Debug("starting udp listener", "address", udpAddr)
		listener, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, listener)
		go s.udpReader(listener)
	}

	<-s.ctx.Done()

	return nil
}

func (s *Server) Finish() {
	defer s.cancel()
	for _, listener := range s.listeners {
		listener.Close()
	}
	for _, worker := range s.workers {
		worker.cancel()
	}
	s.listeners = nil
	s.workers = nil
}

func (s *Server) submitJob(job workerJob) {
	if len(job.message.Questions) == 0 {
		s.workers[0].submit(job)
	} else {
		hasher := fnv.New64()
		hasher.Write([]byte(job.message.Questions[0].Name))
		sum := hasher.Sum64()
		worker := s.workers[sum%uint64(len(s.workers))]
		worker.submit(job)
	}
}

func (s *Server) receiverTcp(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept tcp connection", "error", err)
			continue
		}
		go s.tcpReader(conn)
	}
}

func (s *Server) tcpReader(conn net.Conn) {
	ctx, cancel := context.WithCancel(s.ctx)

	defer conn.Close()
	defer cancel()

	writeChann := make(chan *Message)
	go s.tcpWriter(ctx, conn, writeChann)

	for {
		messageLengthBuf := make([]byte, 2)
		if _, err := conn.Read(messageLengthBuf); err != nil {
			if err != io.EOF {
				slog.Error("failed to read message length from tcp connection", "error", err, "remote", conn.RemoteAddr())
			}
			break
		}

		messageLength := binary.BigEndian.Uint16(messageLengthBuf)
		messageBuf := make([]byte, messageLength)
		if _, err := conn.Read(messageBuf); err != nil {
			slog.Error("failed to read message from tcp connection", "error", err, "remote", conn.RemoteAddr())
			break
		}

		message, err := Decode(messageBuf)
		if err != nil {
			slog.Error("failed to decode message from tcp connection", "error", err, "remote", conn.RemoteAddr())
		}

		job := workerJob{
			message: message,
			responder: func(m *Message) {
				writeChann <- m
			},
		}
		s.submitJob(job)
	}
}

func (s *Server) tcpWriter(ctx context.Context, conn net.Conn, receiver <-chan *Message) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-receiver:
			encoded := EncodeOrServerError(msg, MessageSizeLimitTCP)
			if _, err := conn.Write(encoded); err != nil {
				slog.Error("failed to write to tcp connection", "error", err, "remote", conn.RemoteAddr())
				conn.Close()
				return
			}
		}
	}
}

func (s *Server) udpReader(conn net.PacketConn) {
	defer conn.Close()

	writeChann := make(chan messageWithAddr)
	go s.udpWriter(conn, writeChann)

	for {
		buf := make([]byte, MAX_UDP_MESSAGE_SIZE)
		_, addr, err := conn.ReadFrom(buf)
		if err != nil {
			slog.Warn("failed to read udp message", "error", err)
			continue
		}

		message, err := Decode(buf)
		if err != nil {
			slog.Error("failed to decode message from udp packet", "error", err, "remote", addr)
			continue
		}

		job := workerJob{
			message: message,
			responder: func(m *Message) {
				writeChann <- messageWithAddr{
					message: m,
					addr:    addr,
				}
			},
		}
		s.submitJob(job)
	}
}

func (s *Server) udpWriter(conn net.PacketConn, receiver <-chan messageWithAddr) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg := <-receiver:
			encoded := EncodeOrServerError(msg.message, MessageSizeLimitUDP)
			if _, err := conn.WriteTo(encoded, msg.addr); err != nil {
				slog.Warn("failed to write udp response", "error", err, "remote", msg.addr)
			}
		}
	}
}
