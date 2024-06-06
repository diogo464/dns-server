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

func (r *dnsBuffer) Position() int {
	return r.cursor
}

func (r *dnsBuffer) SetPosition(position int) {
	r.cursor = position
}

func (r *dnsBuffer) Remain() int {
	return len(r.buffer) - r.cursor
}

func (r *dnsBuffer) Read(n int) []byte {
	v := r.buffer[r.cursor : r.cursor+n]
	r.cursor += n
	return v
}

func (r *dnsBuffer) ReadU8() uint8 {
	v := uint8(r.buffer[r.cursor])
	r.cursor += 1
	return v
}

func (r *dnsBuffer) ReadU16() uint16 {
	v := binary.BigEndian.Uint16([]byte{r.buffer[r.cursor], r.buffer[r.cursor+1]})
	r.cursor += 2
	return v
}

func (r *dnsBuffer) ReadU32() uint32 {
	v := binary.BigEndian.Uint32([]byte{r.buffer[r.cursor], r.buffer[r.cursor+1], r.buffer[r.cursor+2], r.buffer[r.cursor+3]})
	r.cursor += 4
	return v
}

func (w *dnsBuffer) WriteU8(v uint8) {
	w.Write([]byte{v})
}

func (w *dnsBuffer) WriteU16(v uint16) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	w.Write(buf)
}

func (w *dnsBuffer) WriteU32(v uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	w.Write(buf)
}

func (w *dnsBuffer) Write(buf []byte) {
	copy(w.buffer[w.cursor:], buf)
	w.cursor += len(buf)
}

func (w *dnsBuffer) Bytes() []byte {
	return w.buffer[:min(w.cursor, len(w.buffer))]
}

func (w *dnsBuffer) Truncated() bool {
	return len(w.buffer) < w.cursor
}
