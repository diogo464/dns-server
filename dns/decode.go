package dns

import (
	"strings"
)

func Decode(b []byte) (*Message, error) {
	buf := newDnsBuffer(b)

	message := &Message{}
	if err := decodeHeader(buf, &message.Header); err != nil {
		return nil, err
	}

	message.Questions = make([]Question, message.Header.QuestionCount)
	message.Answers = make([]RR, message.Header.AnswerCount)
	message.Authority = make([]RR, message.Header.AuthoritativeCount)
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
	header.AuthoritativeCount = buf.ReadU16()
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

func decodeResourceRecord(buf *dnsBuffer) (RR, error) {
	name, err := decodeName(buf)
	if err != nil {
		return RR{}, err
	}

	// TODO: error checking
	ty := buf.ReadU16()
	class := buf.ReadU16()
	ttl := buf.ReadU32()
	dlen := buf.ReadU16()

	header := RR_Header{
		Name:  name,
		Type:  ty,
		Class: class,
		TTL:   ttl,
	}

	switch ty {
	case TYPE_A:
		data := buf.Read(int(dlen))
		return RR{RR_Header: header, Data: &RR_A{Addr: [4]byte{data[0], data[1], data[2], data[3]}}}, nil
	case TYPE_NS:
		nsname, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_NS{Nameserver: nsname}}, nil
	case TYPE_MD:
		agent, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MD{MailAgentDomain: agent}}, nil
	case TYPE_MF:
		agent, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MF{MailAgentDomain: agent}}, nil
	case TYPE_CNAME:
		name, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_CNAME{CNAME: name}}, nil
	case TYPE_SOA:
		mname, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		rname, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		serial := buf.ReadU32()
		refresh := buf.ReadU32()
		retry := buf.ReadU32()
		expire := buf.ReadU32()
		minimum := buf.ReadU32()
		return RR{RR_Header: header, Data: &RR_SOA{
			MNAME:   mname,
			RNAME:   rname,
			SERIAL:  serial,
			REFRESH: refresh,
			RETRY:   retry,
			EXPIRE:  expire,
			MINIMUM: minimum,
		}}, nil
	case TYPE_MB:
		domain, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MB{MailboxDomain: domain}}, nil
	case TYPE_MG:
		domain, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MG{MailGroupDomain: domain}}, nil
	case TYPE_MR:
		name, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MR{NewName: name}}, nil
	case TYPE_NULL:
		data := buf.Read(int(dlen))
		return RR{RR_Header: header, Data: &RR_NULL{Data: data}}, nil
	case TYPE_WKS:
		address := buf.Read(4)
		protocol := buf.ReadU8()
		services := []uint8(buf.Read(int(dlen)))
		return RR{RR_Header: header, Data: &RR_WKS{Address: [4]byte(address), Protocol: protocol, Services: services}}, nil
	case TYPE_PTR:
		name, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_PTR{PTRDNAME: name}}, nil
	case TYPE_HINFO:
		cpu, err := decodeCharacterString(buf)
		if err != nil {
			return RR{}, err
		}
		os, err := decodeCharacterString(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_HINFO{CPU: cpu, OS: os}}, nil
	case TYPE_MINFO:
		rmailbx, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		emailbx, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MINFO{RMAILBX: rmailbx, EMAILBX: emailbx}}, nil
	case TYPE_MX:
		preference := buf.ReadU16()
		exchange, err := decodeName(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_MX{Preference: preference, Exchange: exchange}}, nil
	case TYPE_TXT:
		data, err := decodeCharacterString(buf)
		if err != nil {
			return RR{}, err
		}
		return RR{RR_Header: header, Data: &RR_TXT{Data: data}}, nil
	case TYPE_AXFR:
		return RR{}, ErrNotImplemented
	case TYPE_MAILB:
		return RR{}, ErrNotImplemented
	case TYPE_MAILA:
		return RR{}, ErrNotImplemented
	case TYPE_AAAA:
		data := buf.Read(int(dlen))
		rrdata := &RR_AAAA{Addr: [16]byte(data)}
		copy(rrdata.Addr[:], data)
		return RR{RR_Header: header, Data: rrdata}, nil
	default:
		data := buf.Read(int(dlen))
		return RR{RR_Header: header, Data: &RR_Unknown{Data: data}}, nil
	}
}

func decodeResourceRecords(buf *dnsBuffer, rrs []RR) error {
	for idx := range rrs {
		rr, err := decodeResourceRecord(buf)
		if err != nil {
			return err
		}
		rrs[idx] = rr
	}
	return nil
}

func decodeName(buf *dnsBuffer) (string, error) {
	ptrMask := uint8(0b11000000)
	offset := buf.cursor
	name := ""
	endOffset := -1

	// TODO: check length (characters + length octet) is not greater than 255

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
			if endOffset == -1 {
				endOffset = offset + 2
			}
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

func decodeCharacterString(buf *dnsBuffer) (string, error) {
	l := buf.ReadU8()
	b := buf.Read(int(l))
	return string(b), nil
}
