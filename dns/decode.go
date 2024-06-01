package dns

import "strings"

func Decode(b []byte) (*Message, error) {
	buf := newDnsBuffer(b)

	message := &Message{}
	if err := decodeHeader(buf, &message.Header); err != nil {
		return nil, err
	}

	message.Questions = make([]Question, message.Header.QuestionCount)
	message.Answers = make([]RR, message.Header.AnswerCount)
	message.Authority = make([]RR, message.Header.NameServerCount)
	message.Additional = make([]RR, message.Header.AdditionalCount)

	for i := 0; i < int(message.Header.QuestionCount); i++ {
		if err := decodeQuestion(buf, &message.Questions[i]); err != nil {
			return nil, err
		}
	}

	if err := decodeResourceRecords(buf, message.Answers); err != nil {
		return nil, err
	}

	if err := decodeResourceRecords(buf, message.Authority); err != nil {
		return nil, err
	}

	if err := decodeResourceRecords(buf, message.Additional); err != nil {
		return nil, err
	}

	return message, nil
}

func decodeHeader(buf *dnsBuffer, header *Header) error {
	if buf.Remain() < 12 {
		return ErrInsufficientData
	}

	header.Id = buf.ReadU16()
	flags := buf.ReadU16()
	header.Response = (flags & (1 << 15)) > 0
	header.Opcode = uint8((flags & (0b1111 << 11)) >> 11)
	header.Authoritative = (flags & (1 << 10)) > 0
	header.Truncated = (flags & (1 << 9)) > 0
	header.RecursionDesired = (flags & (1 << 8)) > 0
	header.RecursionAvailable = (flags & (1 << 7)) > 0
	header.ResponseCode = uint8(flags & 0b1111)
	header.QuestionCount = buf.ReadU16()
	header.AnswerCount = buf.ReadU16()
	header.NameServerCount = buf.ReadU16()
	header.AdditionalCount = buf.ReadU16()

	return nil
}

func decodeQuestion(buf *dnsBuffer, question *Question) error {
	name, err := decodeName(buf)
	if err != nil {
		return err
	}

	ty := buf.ReadU16()
	class := buf.ReadU16()

	question.Name = name
	question.Type = ty
	question.Class = class

	return nil
}

func decodeResourceRecord(buf *dnsBuffer, rr *RR) error {
	name, err := decodeName(buf)
	if err != nil {
		return err
	}

	// TODO: error checking
	ty := buf.ReadU16()
	class := buf.ReadU16()
	ttl := buf.ReadU16()
	dlen := buf.ReadU16()
	data := buf.Read(int(dlen))

	rr.Name = name
	rr.Type = ty
	rr.Class = class
	rr.TTL = ttl
	rr.Data = data

	return nil
}

func decodeResourceRecords(buf *dnsBuffer, rrs []RR) error {
	for idx := range rrs {
		if err := decodeResourceRecord(buf, &rrs[idx]); err != nil {
			return err
		}
	}
	return nil
}

func decodeName(buf *dnsBuffer) (string, error) {
	ptrMask := uint8(0b11000000)
	offset := buf.cursor
	name := ""
	endOffset := -1

	for {
		llen := uint8(buf.buffer[offset])
		isPtr := llen&ptrMask == ptrMask
		llen = llen & ^ptrMask

		if !isPtr && llen == 0 {
			if endOffset == -1 {
				buf.cursor = offset + 1
			} else {
				buf.cursor = endOffset
			}
			break
		}

		if isPtr {
			lhs := uint16(llen)
			rhs := uint16(buf.buffer[offset+1])
			endOffset = offset + 2
			offset = int(lhs<<8 | rhs)
		} else {
			label := string(buf.buffer[offset+1 : offset+1+int(llen)])
			offset += 1 + int(llen)
			name += label + "."
		}
	}

	name = strings.TrimRight(name, ".")

	return name, nil
}
