package dns

func Encode(message *Message) []byte {
	buf := newDnsBuffer(make([]byte, 512))
	encodeHeader(buf, &message.Header)
	encodeQuestions(buf, message.Questions)
	encodeResourceRecords(buf, message.Answers)
	encodeResourceRecords(buf, message.Authority)
	encodeResourceRecords(buf, message.Additional)
	return buf.Bytes()
}

func encodeU16Bit(v bool, bit int) uint16 {
	if v {
		return 1 << bit
	}
	return 0
}

func encodeU16Int(v uint16, bits, offset int) uint16 {
	return (v & (0xFFFF >> (16 - bits))) << offset
}

func encodeHeader(buf *dnsBuffer, header *Header) {
	buf.WriteU16(header.Id)

	flags := uint16(0)
	flags |= encodeU16Bit(header.Response, 15)
	flags |= encodeU16Int(uint16(header.Opcode), 4, 11)
	flags |= encodeU16Bit(header.Authoritative, 10)
	flags |= encodeU16Bit(header.Truncated, 9)
	flags |= encodeU16Bit(header.RecursionDesired, 8)
	flags |= encodeU16Bit(header.RecursionAvailable, 7)
	flags |= encodeU16Int(uint16(header.ResponseCode), 4, 0)
	buf.WriteU16(flags)

	buf.WriteU16(header.QuestionCount)
	buf.WriteU16(header.AnswerCount)
	buf.WriteU16(header.AuthoritativeCount)
	buf.WriteU16(header.AdditionalCount)
}

func encodeQuestion(buf *dnsBuffer, q *Question) error {
	if err := encodeName(buf, q.Name); err != nil {
		return err
	}
	buf.WriteU16(q.Type)
	buf.WriteU16(q.Class)
	return nil
}

func encodeQuestions(buf *dnsBuffer, qs []Question) {
	for _, q := range qs {
		encodeQuestion(buf, &q)
	}
}

func encodeResourceRecord(buf *dnsBuffer, rr RR) error {
	header := rr.Header()
	if err := encodeName(buf, header.Name); err != nil {
		return err
	}
	buf.WriteU16(header.Type)
	buf.WriteU16(header.Class)
	buf.WriteU32(header.TTL)
	rr.writeData(buf) // TODO: handle error

	// if len(rr.Data) > 0xFFFF {
	// 	return ErrResourceRecordDataToLarge
	// }
	// buf.WriteU16(uint16(len(rr.Data)))
	// buf.Write(rr.Data)

	return nil
}

func encodeResourceRecords(buf *dnsBuffer, rrs []RR) {
	for _, rr := range rrs {
		encodeResourceRecord(buf, rr)
	}
}

func encodeLabel(buf *dnsBuffer, label string) error {
	if len(label) > MAX_LABEL_SIZE {
		return ErrLabelToLarge
	}

	buf.WriteU8(uint8(len(label)))
	buf.Write([]byte(label))

	return nil
}

func encodeName(buf *dnsBuffer, name string) error {
	labels := splitNameIntoLabels(name)
	for _, label := range labels {
		if err := encodeLabel(buf, label); err != nil {
			return err
		}
	}
	encodeLabel(buf, "")
	return nil
}
