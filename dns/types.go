package dns

import (
	"fmt"
	"net"
)

var ErrInsufficientData = fmt.Errorf("insufficient data while decoding message")
var ErrLabelToLarge = fmt.Errorf("label length exceeds allowed 63 bytes")
var ErrCharacterStringToLarge = fmt.Errorf("character string exceeds allowed 255 bytes")
var ErrRDataToLarge = fmt.Errorf("rdata field exceeds allowed size")
var ErrResourceRecordDataToLarge = fmt.Errorf("resource record data is to large")
var ErrInvalidRRType = fmt.Errorf("invalid RR type")
var ErrInvalidRRData = fmt.Errorf("invalid RR data")
var ErrNotImplemented = fmt.Errorf("not implemented")

const MAX_LABEL_SIZE = 63
const MAX_UDP_MESSAGE_SIZE = 512

const (
	OPCODE_QUERY uint8 = iota
	OPCODE_IQUERY
	OPCODE_STATUS
)

const (
	// No error condition
	RCODE_NO_ERROR uint8 = iota
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
	TYPE_NS // Authoritative name server
	TYPE_MD
	TYPE_MF
	TYPE_CNAME
	TYPE_SOA
	TYPE_MB
	TYPE_MG
	TYPE_MR
	TYPE_NULL
	TYPE_WKS
	TYPE_PTR
	TYPE_HINFO
	TYPE_MINFO
	TYPE_MX
	TYPE_TXT
	TYPE_AXFR
	TYPE_MAILB
	TYPE_MAILA
	TYPE_AAAA = 28
	TYPE_ANY  = 255
)

var TypeString map[uint16]string = map[uint16]string{
	TYPE_A:     "A",
	TYPE_MD:    "MD",
	TYPE_MF:    "MF",
	TYPE_CNAME: "CNAME",
	TYPE_SOA:   "SOA",
	TYPE_MB:    "MB",
	TYPE_MG:    "MG",
	TYPE_MR:    "MR",
	TYPE_NULL:  "NULL",
	TYPE_WKS:   "WKS",
	TYPE_PTR:   "PTR",
	TYPE_HINFO: "HINFO",
	TYPE_MINFO: "MINFO",
	TYPE_MX:    "MX",
	TYPE_TXT:   "TXT",
	TYPE_AXFR:  "AXFR",
	TYPE_MAILB: "MAILB",
	TYPE_MAILA: "MAILA",
	TYPE_NS:    "NS",
	TYPE_AAAA:  "AAAA",
}

const (
	_ uint16 = iota
	CLASS_IN
	CLASS_CS
	CLASS_CH
	CLASS_HS

	QCLASS_ANY = 255
)

var ClassString map[uint16]string = map[uint16]string{
	CLASS_IN: "IN",
	CLASS_CS: "CS",
	CLASS_CH: "CH",
	CLASS_HS: "HS",

	QCLASS_ANY: "ANY",
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

var _ RR = (*RR_CNAME)(nil)

type RR_CNAME struct {
	RR_Header
	CNAME string
}

// Header implements RR.
func (r *RR_CNAME) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_CNAME) String() string {
	return resourceRecordToString(&r.RR_Header, r.Name)
}

// writeData implements RR.
func (r *RR_CNAME) writeData(buf *dnsBuffer) {
	encodeName(buf, r.Name)
}

var _ RR = (*RR_HINFO)(nil)

type RR_HINFO struct {
	RR_Header
	CPU string
	OS  string
}

// Header implements RR.
func (r *RR_HINFO) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_HINFO) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("'%v' '%v'", r.CPU, r.OS))
}

// writeData implements RR.
func (r *RR_HINFO) writeData(buf *dnsBuffer) {
	// TODO: handle errors
	encodeCharacterString(buf, r.CPU)
	encodeCharacterString(buf, r.OS)
}

var _ RR = (*RR_MB)(nil)

type RR_MB struct {
	RR_Header
	MailboxDomain string
}

// Header implements RR.
func (r *RR_MB) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MB) String() string {
	return resourceRecordToString(&r.RR_Header, r.MailboxDomain)
}

// writeData implements RR.
func (r *RR_MB) writeData(buf *dnsBuffer) {
	encodeName(buf, r.MailboxDomain)
}

var _ RR = (*RR_MD)(nil)

type RR_MD struct {
	RR_Header
	MailAgentDomain string
}

// Header implements RR.
func (r *RR_MD) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MD) String() string {
	return resourceRecordToString(&r.RR_Header, r.MailAgentDomain)
}

// writeData implements RR.
func (r *RR_MD) writeData(buf *dnsBuffer) {
	// TODO: handle error
	encodeName(buf, r.MailAgentDomain)
}

var _ RR = (*RR_MF)(nil)

type RR_MF struct {
	RR_Header
	MailAgentDomain string
}

// Header implements RR.
func (r *RR_MF) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MF) String() string {
	return resourceRecordToString(&r.RR_Header, r.MailAgentDomain)
}

// writeData implements RR.
func (r *RR_MF) writeData(buf *dnsBuffer) {
	// TODO: handle error
	encodeName(buf, r.MailAgentDomain)
}

var _ RR = (*RR_MG)(nil)

type RR_MG struct {
	RR_Header
	MailGroupDomain string
}

// Header implements RR.
func (r *RR_MG) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MG) String() string {
	return resourceRecordToString(&r.RR_Header, r.MailGroupDomain)
}

// writeData implements RR.
func (r *RR_MG) writeData(buf *dnsBuffer) {
	encodeName(buf, r.MailGroupDomain)
}

var _ RR = (*RR_MINFO)(nil)

type RR_MINFO struct {
	RR_Header
	RMAILBX string
	EMAILBX string
}

// Header implements RR.
func (r *RR_MINFO) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MINFO) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("%v %v", r.RMAILBX, r.EMAILBX))
}

// writeData implements RR.
func (r *RR_MINFO) writeData(buf *dnsBuffer) {
	// TODO: handle errors
	encodeName(buf, r.RMAILBX)
	encodeName(buf, r.EMAILBX)
}

var _ RR = (*RR_MR)(nil)

type RR_MR struct {
	RR_Header
	NewName string
}

// Header implements RR.
func (r *RR_MR) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MR) String() string {
	return resourceRecordToString(&r.RR_Header, r.NewName)
}

// writeData implements RR.
func (r *RR_MR) writeData(buf *dnsBuffer) {
	// TODO: handle error
	encodeName(buf, r.NewName)
}

var _ RR = (*RR_MX)(nil)

type RR_MX struct {
	RR_Header
	Preference uint16
	Exchange   string
}

// Header implements RR.
func (r *RR_MX) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_MX) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("%v %v", r.Preference, r.Exchange))
}

// writeData implements RR.
func (r *RR_MX) writeData(buf *dnsBuffer) {
	buf.WriteU16(r.Preference)
	encodeName(buf, r.Exchange)
}

var _ RR = (*RR_NULL)(nil)

type RR_NULL struct {
	RR_Header
	Data []byte
}

// Header implements RR.
func (r *RR_NULL) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_NULL) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("[%v bytes]", len(r.Data)))
}

// writeData implements RR.
func (r *RR_NULL) writeData(buf *dnsBuffer) {
	if len(r.Data) > 65535 {
		// TODO: handle error
		// return ErrRDataToLarge
	}
	buf.Write(r.Data)
}

var _ RR = (*RR_PTR)(nil)

type RR_PTR struct {
	RR_Header
	PTRDNAME string
}

// Header implements RR.
func (r *RR_PTR) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_PTR) String() string {
	return resourceRecordToString(&r.RR_Header, r.PTRDNAME)
}

// writeData implements RR.
func (r *RR_PTR) writeData(buf *dnsBuffer) {
	// TODO: handle error
	encodeName(buf, r.PTRDNAME)
}

var _ RR = (*RR_SOA)(nil)

type RR_SOA struct {
	RR_Header
	MNAME   string
	RNAME   string
	SERIAL  uint32
	REFRESH uint32
	RETRY   uint32
	EXPIRE  uint32
	MINIMUM uint32
}

// Header implements RR.
func (r *RR_SOA) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_SOA) String() string {
	return resourceRecordToString(&r.RR_Header, r.MNAME, r.RNAME, r.SERIAL, r.REFRESH, r.RETRY, r.EXPIRE, r.MINIMUM)
}

// writeData implements RR.
func (r *RR_SOA) writeData(buf *dnsBuffer) {
	// TODO: handle errors
	encodeName(buf, r.MNAME)
	encodeName(buf, r.RNAME)
	buf.WriteU32(r.SERIAL)
	buf.WriteU32(r.REFRESH)
	buf.WriteU32(r.RETRY)
	buf.WriteU32(r.EXPIRE)
	buf.WriteU32(r.MINIMUM)
}

var _ RR = (*RR_TXT)(nil)

type RR_TXT struct {
	RR_Header
	Data string
}

// Header implements RR.
func (r *RR_TXT) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_TXT) String() string {
	return resourceRecordToString(&r.RR_Header, r.Data)
}

// writeData implements RR.
func (r *RR_TXT) writeData(buf *dnsBuffer) {
	// TODO: handle error
	// TODO: RFC1035 says one or more character strings, this implementation might be incorrect.
	encodeCharacterString(buf, r.Data)
}

var _ RR = (*RR_WKS)(nil)

type RR_WKS struct {
	RR_Header
	Address  [4]byte
	Protocol uint8
	Services []uint8
}

// Header implements RR.
func (r *RR_WKS) Header() RR_Header {
	return r.RR_Header
}

// String implements RR.
func (r *RR_WKS) String() string {
	return resourceRecordToString(&r.RR_Header, fmt.Sprintf("%v.%v.%v.%v", r.Address[3], r.Address[2], r.Address[1], r.Address[0]), r.Protocol)
}

// writeData implements RR.
func (r *RR_WKS) writeData(buf *dnsBuffer) {
	buf.Write(r.Address[:])
	buf.WriteU8(r.Protocol)
	for _, v := range r.Services {
		buf.WriteU8(v)
	}
}

func resourceRecordToString(header *RR_Header, extra ...any) string {
	v := fmt.Sprintf("%v\t%v\t%v\t%v", header.Name, header.TTL, classToString(header.Class), typeToString(header.Type))
	for _, x := range extra {
		v += "\t" + fmt.Sprint(x)
	}
	return v
}
