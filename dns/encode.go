package dns

func EncodeOrServerError(message *Message, messageSizeLimit int) []byte {
	encoded, err := Encode(message, messageSizeLimit)
	if err == nil {
		return encoded
	} else {
		encodedErr, _ := Encode(createErrorResponseMessage(message, RCODE_SERVER_FAILURE), messageSizeLimit)
		return encodedErr
	}
}

func Encode(message *Message, messageSizeLimit int) ([]byte, error) {
	buf := newDnsBuffer(make([]byte, messageSizeLimit))
	encodeHeader(buf, &message.Header)
	if err := encodeQuestions(buf, message.Questions); err != nil {
		return nil, err
	}
	if err := encodeResourceRecords(buf, message.Answers); err != nil {
		return nil, err
	}
	if err := encodeResourceRecords(buf, message.Authority); err != nil {
		return nil, err
	}
	if err := encodeResourceRecords(buf, message.Additional); err != nil {
		return nil, err
	}
	if buf.Truncated() {
		header := message.Header
		header.Truncated = true
		prevPosition := buf.Position()
		buf.SetPosition(0)
		encodeHeader(buf, &header)
		buf.SetPosition(prevPosition)
	}
	return buf.Bytes(), nil
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

func encodeQuestions(buf *dnsBuffer, qs []Question) error {
	for _, q := range qs {
		if err := encodeQuestion(buf, &q); err != nil {
			return err
		}
	}
	return nil
}

func encodeResourceRecord(buf *dnsBuffer, rr RR) error {
	header := rr.RR_Header
	if err := encodeName(buf, header.Name); err != nil {
		return err
	}
	buf.WriteU16(header.Type)
	buf.WriteU16(header.Class)
	buf.WriteU32(header.TTL)

	startPos := buf.Position()
	buf.WriteU16(0)
	if err := rr.Data.writeData(buf); err != nil {
		return err
	}
	endPos := buf.Position()
	dataLen := uint16(endPos - startPos - 2)
	buf.SetPosition(startPos)
	buf.WriteU16(dataLen)
	buf.SetPosition(endPos)

	return nil
}

func encodeResourceRecords(buf *dnsBuffer, rrs []RR) error {
	for _, rr := range rrs {
		if err := encodeResourceRecord(buf, rr); err != nil {
			return err
		}
	}
	return nil
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

func encodeCharacterString(buf *dnsBuffer, v string) error {
	if len(v) > 255 {
		return ErrCharacterStringToLarge
	}
	buf.WriteU8(uint8(len(v)))
	buf.Write([]byte(v))
	return nil
}
