package dns

import "fmt"

var ErrInsufficientData = fmt.Errorf("insufficient data while decoding message")
var ErrLabelToLarge = fmt.Errorf("label length exceeds allowed 63 bytes")
var ErrResourceRecordDataToLarge = fmt.Errorf("resource record data is to large")

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
)

const (
	_ uint16 = iota
	CLASS_IN
)

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
	NameServerCount    uint16
	AdditionalCount    uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint16
	Data  []byte
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}
