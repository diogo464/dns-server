package dns

import "encoding/binary"

type dnsBuffer struct {
	buffer []byte
	cursor int
}

func newDnsBuffer(buf []byte) *dnsBuffer {
	return &dnsBuffer{
		buffer: buf,
		cursor: 0,
	}
}

func (r *dnsBuffer) Remain() int {
	return len(r.buffer) - r.cursor
}

func (r *dnsBuffer) Read(n int) []byte {
	v := r.buffer[r.cursor : r.cursor+n]
	r.cursor += n
	return v
}

func (r *dnsBuffer) ReadU16() uint16 {
	v := binary.BigEndian.Uint16([]byte{r.buffer[r.cursor], r.buffer[r.cursor+1]})
	r.cursor += 2
	return v
}

func (w *dnsBuffer) WriteU8(v uint8) {
	w.buffer[w.cursor] = byte(v)
	w.cursor += 1
}

func (w *dnsBuffer) WriteU16(v uint16) {
	binary.BigEndian.PutUint16(w.buffer[w.cursor:w.cursor+2], v)
	w.cursor += 2
}

func (w *dnsBuffer) Write(buf []byte) {
	copy(w.buffer[w.cursor:], buf)
	w.cursor += len(buf)
}

func (w *dnsBuffer) Bytes() []byte {
	return w.buffer[:w.cursor]
}
