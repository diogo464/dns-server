package dns

import (
	"fmt"
	"net"
)

var ErrInsufficientData = fmt.Errorf("insufficient data while decoding message")
var ErrLabelToLarge = fmt.Errorf("label length exceeds allowed 63 bytes")
var ErrResourceRecordDataToLarge = fmt.Errorf("resource record data is to large")
var ErrInvalidRRType = fmt.Errorf("invalid RR type")
var ErrInvalidRRData = fmt.Errorf("invalid RR data")

const MAX_LABEL_SIZE = 63

const (
	OPCODE_QUERY uint8 = iota
	OPCODE_IQUERY
	OPCODE_STATUS
)

const (
	// No error condition
	RCODE_NO_ERROR = iota
	// The name server was unable to interpret the query
	RCODE_FORMAT_ERROR
	// The name server was unable to process this query due to a problem with the name server
	RCODE_SERVER_FAILURE
	// The domain referenced in query does not exist.
	// Only meaningful for authoritative responses.
	RCODE_NAME_ERROR
	// The name server does not support the requested kind of query
	RCODE_NOT_IMPLEMENTED
	// The name server refuses to perform the specified operation for policy reasons.
	RCODE_REFUSED
)

const (
	_ uint16 = iota
	TYPE_A
	TYPE_NS   // Authoritative name server
	TYPE_AAAA = 28
	TYPE_ANY  = 255
)

var TypeString map[uint16]string = map[uint16]string{
	TYPE_A:    "A",
	TYPE_NS:   "NS",
	TYPE_AAAA: "AAAA",
}

const (
	_ uint16 = iota
	CLASS_IN
)

var ClassString map[uint16]string = map[uint16]string{
	CLASS_IN: "IN",
}

type sockAddr struct {
	Ip   net.IP
	Port uint16
}

func (addr *sockAddr) String() string {
	return fmt.Sprintf("[%v]:%v", addr.Ip, addr.Port)
}

type Header struct {
	Id                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	ResponseCode       uint8
	QuestionCount      uint16
	AnswerCount        uint16
	AuthoritativeCount uint16
	AdditionalCount    uint16
}

func (h *Header) String() string {
	return fmt.Sprintf("ID: %v\tResponse: %v\tOpcode: %v\nAA: %v TC: %v RD: %v RA: %v\nQDCOUNT: %v\tANCOUNT: %v\tNSCOUNT: %v\tARCOUNT: %v", h.Id, h.Response, h.Opcode, h.Authoritative, h.Truncated, h.RecursionDesired, h.RecursionAvailable, h.QuestionCount, h.AnswerCount, h.AuthoritativeCount, h.AdditionalCount)
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *Question) String() string {
	return fmt.Sprintf("%v\t%v\t%v", q.Name, classToString(q.Class), typeToString(q.Type))
}

type RR interface {
	fmt.Stringer
	Header() RR_Header
	writeData(buf *dnsBuffer)
}

type RR_Header struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

func (m *Message) String() string {
	str := ""
	str += m.Header.String() + "\n"
	for _, q := range m.Questions {
		str += q.String() + "\n"
	}
	str += "\n;; Answer\n"
	for _, r := range m.Answers {
		str += r.String() + "\n"
	}
	str += "\n;; Authority\n"
	for _, r := range m.Authority {
		str += r.String() + "\n"
	}
	str += "\n;; Additional\n"
	for _, r := range m.Additional {
		str += r.String() + "\n"
	}
	return str
}

var _ RR = (*RR_Unknown)(nil)

type RR_Unknown struct {
	RR_Header
	Data []byte
}

// Header implements RR.
func (r *RR_Unknown) Header() RR_Header {
	return r.RR_Header
}

// writeData implements RR.
func (r *RR_Unknown) writeData(buf *dnsBuffer) {
	buf.WriteU16(uint16(len(r.Data)))
	buf.Write(r.Data)
}

// String implements RR.
func (r *RR_Unknown) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("[unknown %v bytes]", len(r.Data)))
}

var _ RR = (*RR_A)(nil)

type RR_A struct {
	RR_Header
	Addr [4]byte
}

// String implements RR.
func (rr *RR_A) String() string {
	return resourceRecordToString(&rr.RR_Header, fmt.Sprintf("%v.%v.%v.%v", rr.Addr[3], rr.Addr[2], rr.Addr[1], rr.Addr[0]))
}

// Header implements RR.
func (rr *RR_A) Header() RR_Header {
	return rr.RR_Header
}

// writeData implements RR.
func (rr *RR_A) writeData(buf *dnsBuffer) {
	buf.WriteU16(4)
	buf.Write(rr.Addr[:])
}

func (rr *RR_A) ToNetIp() net.IP {
	return net.IPv4(rr.Addr[3], rr.Addr[2], rr.Addr[1], rr.Addr[0])
}

var _ RR = (*RR_AAAA)(nil)

type RR_AAAA struct {
	RR_Header
	Addr [16]byte
}

func (rr *RR_AAAA) ToNetIp() net.IP {
	return net.IP(rr.Addr[:])
}

// Header implements RR.
func (r *RR_AAAA) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_AAAA) String() string {
	return resourceRecordToString(&r.RR_Header, net.IP.To16(r.ToNetIp()).String())
}

// writeData implements RR.
func (r *RR_AAAA) writeData(buf *dnsBuffer) {
	buf.WriteU16(16)
	buf.Write(r.Addr[:])
}

var _ RR = (*RR_NS)(nil)

type RR_NS struct {
	RR_Header
	Nameserver string
}

// Header implements RR.
func (r *RR_NS) Header() RR_Header {
	return r.RR_Header
}

// writeData implements RR.
func (r *RR_NS) writeData(buf *dnsBuffer) {
	startPos := buf.Position()
	buf.WriteU16(0)
	encodeName(buf, r.Nameserver) // TODO: handle error
	endPos := buf.Position()

	nameLen := uint16(endPos - startPos - 2)
	buf.SetPosition(startPos)
	buf.WriteU16(nameLen)
	buf.SetPosition(endPos)
}

// String implements RR.
func (r *RR_NS) String() string {
	return resourceRecordToString(&r.RR_Header, r.Nameserver)
}

func resourceRecordToString(header *RR_Header, extra string) string {
	return fmt.Sprintf("%v\t%v\t%v\t%v\t%v", header.Name, header.TTL, classToString(header.Class), typeToString(header.Type), extra)
}
