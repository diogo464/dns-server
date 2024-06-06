package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"net"
)

const defaultWorkerChannSize = 64

type workerJob struct {
	message   *Message
	responder func(*Message)
}

type worker struct {
	ctx            context.Context
	cancel         context.CancelFunc
	chann          chan workerJob
	authorityCache AuthorityCache
	resourceCache  ResourceCache
}

func newWorker(authorityCache AuthorityCache, resourceCache ResourceCache) *worker {
	chann := make(chan workerJob, defaultWorkerChannSize)
	ctx, cancel := context.WithCancel(context.Background())
	return &worker{
		ctx:            ctx,
		cancel:         cancel,
		chann:          chann,
		authorityCache: authorityCache,
		resourceCache:  resourceCache,
	}
}

func (w *worker) submit(job workerJob) {
	w.chann <- job
}

func (w *worker) run() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case j := <-w.chann:
			response := w.process(j)
			j.responder(response)
		}
	}
}

func (w *worker) process(job workerJob) *Message {
	slog.Info("processing job")
	if debugLogEnabled() {
		fmt.Println(job.message)
	}

	msg := job.message

	if msg.Header.Response {
		slog.Warn("received message with response flag set")
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	if msg.Header.Opcode != OPCODE_QUERY {
		slog.Warn("received message with opcode != OPCODE_QUERY", "opcode", msg.Header.Opcode)
		return createErrorResponseMessage(msg, RCODE_NOT_IMPLEMENTED)
	}

	if msg.Header.QuestionCount != 1 {
		slog.Warn("received message with incorrect number of questions", "questions", msg.Header.QuestionCount)
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	if msg.Header.AnswerCount != 0 || msg.Header.AuthoritativeCount != 0 || msg.Header.AdditionalCount != 0 {
		slog.Warn("received message with resource records")
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	question := msg.Questions[0]

	if question.Class != CLASS_IN {
		slog.Warn("received message with question class != CLASS_IN", "class", question.Class)
		return createErrorResponseMessage(msg, RCODE_NOT_IMPLEMENTED)
	}

	rrs := w.resolve(question.Name, question.Type, make(map[string]struct{}))
	if rrs == nil {
		return createErrorResponseMessage(msg, RCODE_SERVER_FAILURE)
	}

	response := &Message{}
	response.Header.Id = msg.Header.Id
	response.Header.Response = true
	response.Header.RecursionAvailable = true
	response.Header.RecursionDesired = msg.Header.RecursionDesired
	response.Header.ResponseCode = RCODE_NO_ERROR
	response.Header.QuestionCount = msg.Header.QuestionCount
	response.Header.AnswerCount = uint16(len(rrs))
	response.Questions = msg.Questions
	response.Answers = rrs

	if debugLogEnabled() {
		fmt.Println("response")
		fmt.Println(response)
	}

	return response
}

// resolve the name following CNAMEs if necessary
func (w *worker) resolve(name string, ty uint16, visitedCNAMEs map[string]struct{}) []RR {
	if ip, ok := RootNameServersIpv4[name]; ok {
		return []RR{{
			RR_Header: RR_Header{
				Name:  name,
				Type:  ty,
				Class: CLASS_IN,
			},
			Data: &RR_A{Addr: ip},
		}}
	}

	if rrs := w.resourceCache.Get(name, ty); rrs != nil {
		return rrs
	}

	// find the best nameservers and use the slice as a queue
	nameservers := FindBestAuthorityServers(w.authorityCache, name)

	resolveAnswer := make([]RR, 0)
	for {
		if len(nameservers) == 0 {
			break
		}

		nameserver := nameservers[len(nameservers)-1]
		nameservers = nameservers[:len(nameservers)-1]
		nameserverrrs := w.resolve(nameserver, TYPE_A, visitedCNAMEs)
		nameserverips := extractIpsFromRRs(nameserverrrs)
		if len(nameserverips) == 0 {
			continue
		}

		sockaddrs := make([]sockAddr, len(nameserverips))
		for idx, ip := range nameserverips {
			sockaddrs[idx] = sockAddr{
				Ip:   ip,
				Port: 53,
			}
		}

		resp, err := requestTcpAny(sockaddrs, name, ty)
		if err != nil {
			slog.Warn("failed to request", "error", err, "nameserver", nameserver)
			continue
		}

		if len(resp.Answers) != 0 {
			resolveAnswer = resp.Answers
			break
		}

		zoneAuthoritiesMinTTL := uint32(math.MaxUint32)
		zoneAuthorities := make(map[string][]string)
		for _, rr := range resp.Authority {
			if rr_ns, ok := rr.Data.(*RR_NS); ok {
				zoneAuthorities[rr.Name] = append(zoneAuthorities[rr.Name], rr_ns.Nameserver)
				zoneAuthoritiesMinTTL = min(zoneAuthoritiesMinTTL, rr.TTL)
			}
		}

		for zone, zoneNameservers := range zoneAuthorities {
			w.authorityCache.Put(zone, zoneNameservers, zoneAuthoritiesMinTTL)
			for _, nameserver := range zoneNameservers {
				nameservers = append(nameservers, nameserver)
			}
		}

		for _, rr := range resp.Additional {
			if rr.Type == TYPE_A || rr.Type == TYPE_AAAA {
				w.resourceCache.Put(rr.Name, rr.Type, []RR{rr})
			}
		}
	}

	for _, rr := range resolveAnswer {
		if rr.Type == TYPE_CNAME && ty != TYPE_CNAME {
			cname := rr.Data.(*RR_CNAME)
			if _, visited := visitedCNAMEs[cname.CNAME]; !visited {
				visitedCNAMEs[cname.CNAME] = struct{}{}
				cnamerrs := w.resolve(cname.CNAME, ty, visitedCNAMEs)
				if cnamerrs == nil {
					slog.Warn("failed to resolve cname", "cname", cname.CNAME)
					return nil
				}
				for _, cnamerr := range cnamerrs {
					resolveAnswer = append(resolveAnswer, cnamerr)
				}
			}
		}
	}

	w.resourceCache.Put(name, ty, resolveAnswer)

	return resolveAnswer
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

	if debugLogEnabled() {
		fmt.Println("server response")
		fmt.Println(resp)
	}

	return resp, nil
}
