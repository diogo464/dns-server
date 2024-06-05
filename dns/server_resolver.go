package dns

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
)

// TODO: follow CNAMEs

type workerResolver struct {
	// keep track of resolved domains for the current query to prevent loops due to CNAMEs
	resolvedDomains map[string]struct{}
	// keep track of resolved authority name servers to prevent loops
	resolvedNameservers map[string]struct{}
}

func newWorkerResolver() *workerResolver {
	return &workerResolver{}
}

func (r *workerResolver) Resolve(name string, ty uint16) ([]RR, error) {
	r.resolvedDomains = make(map[string]struct{})
	r.resolvedNameservers = make(map[string]struct{})
	return r.resolveRecursive(name, ty)
}

func (r *workerResolver) resolveRecursive(name string, ty uint16) ([]RR, error) {
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
			if ty != TYPE_CNAME {
				if rrdata, iscname := response.Answers[0].Data.(*RR_CNAME); iscname {
					if _, isresolved := r.resolvedDomains[rrdata.CNAME]; !isresolved {
						r.resolvedDomains[rrdata.CNAME] = struct{}{}
						cnamerrs, err := r.resolveRecursive(rrdata.CNAME, ty)
						if err != nil {
							return nil, err
						}
						for _, rr := range cnamerrs {
							response.Answers = append(response.Answers, rr)
						}
					}
				}
			}
			return response.Answers, nil
		}

		if len(response.Authority) == 0 {
			break
		}

		authorities := make(map[string]struct{})
		for _, rr := range response.Authority {
			rr_ns, ok := rr.Data.(*RR_NS)
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
				delete(authorities, rr.Name)
			}
		}

		// resolve names of missing authority servers
		for authority := range authorities {
			if _, ok := r.resolvedNameservers[authority]; ok {
				continue
			}
			// set the server as resolved before actually resolving it so we can ignore it if it tries to be resolved inside this next resolve
			r.resolvedNameservers[authority] = struct{}{}

			rrs, err := r.resolveRecursive(authority, TYPE_A)
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
	msg.Header.Id = genRandomId()
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

	if resp.Header.Id != msg.Header.Id {
		slog.Debug("received incorrect message id")
		return nil, ErrIncorrectIdReceived
	}

	fmt.Println("server response")
	fmt.Println(resp)

	return resp, nil
}
