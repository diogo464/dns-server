package dns

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
)

func Resolve(name string, ty uint16) ([]RR, error) {
	nextServers := []sockAddr{}
	for _, ip := range RootServersIpv4 {
		nextServers = append(nextServers, sockAddr{
			Ip:   ip,
			Port: 53,
		})
	}

	for {
		response, err := requestTcpAny(nextServers, name, ty)
		if err != nil {
			return nil, err
		}

		if len(response.Answers) > 0 {
			return response.Answers, nil
		}

		if len(response.Authority) == 0 {
			break
		}

		authorities := make(map[string]struct{})
		for _, rr := range response.Authority {
			rr_ns, ok := rr.(*RR_NS)
			if !ok {
				continue
			}

			authorities[rr_ns.Nameserver] = struct{}{}
		}

		nextServers = nil
		for _, rr := range response.Additional {
			if ip := extractIpFromRR(rr); ip != nil {
				nextServers = append(nextServers, sockAddr{
					Ip:   ip,
					Port: 53,
				})
				delete(authorities, rr.Header().Name)
			}
		}

		// resolve names of missing authority servers
		for authority := range authorities {
			rrs, err := Resolve(authority, TYPE_A)
			if err != nil {
				slog.Debug("failed to resolve authority server address", "authority", authority, "error", err)
				continue
			}

			for _, ip := range extractIpsFromRRs(rrs) {
				nextServers = append(nextServers, sockAddr{
					Ip:   ip,
					Port: 53,
				})
			}
		}
	}
	return nil, fmt.Errorf("failed to resolve name")
}

func requestTcpAny(addrs []sockAddr, name string, ty uint16) (*Message, error) {
	lastErr := fmt.Errorf("no servers available")
	for _, addr := range addrs {
		slog.Debug("sending request", "address", addr)
		if msg, err := requestTcp(addr, name, ty); err == nil {
			slog.Debug("received response", "response", msg)
			return msg, nil
		} else {
			lastErr = err
			slog.Debug("failed to send request, trying next server", "address", addr, "error", err)
		}
	}
	return nil, lastErr
}

func requestTcp(addr sockAddr, name string, ty uint16) (*Message, error) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		slog.Debug("failed to dial dns server", "address", addr, "error", err)
		return nil, err
	}

	msg := Message{}
	msg.Header.Opcode = OPCODE_QUERY
	msg.Header.QuestionCount = 1
	msg.Questions = []Question{
		{
			Name:  name,
			Type:  ty,
			Class: CLASS_IN,
		},
	}

	encodedRequest := Encode(&msg)
	encodedLength := make([]byte, 2)
	binary.BigEndian.PutUint16(encodedLength, uint16(len(encodedRequest)))
	if _, err := conn.Write(encodedLength); err != nil {
		slog.Debug("failed to write request length", "error", err)
		return nil, err
	}
	if _, err := conn.Write(encodedRequest); err != nil {
		slog.Debug("failed to write request", "error", err)
		return nil, err
	}

	msgLen := make([]byte, 2)
	if _, err := conn.Read(msgLen); err != nil {
		slog.Debug("failed to read message length", "error", err)
		return nil, err
	}
	mlen := binary.BigEndian.Uint16(msgLen)

	buf := make([]byte, mlen)
	_, err = conn.Read(buf)
	if err != nil {
		slog.Debug("failed to read response", "error", err)
		return nil, err
	}

	resp, err := Decode(buf)
	if err != nil {
		slog.Debug("failed to decoded response", "error", err)
		return nil, err
	}

	return resp, nil
}
