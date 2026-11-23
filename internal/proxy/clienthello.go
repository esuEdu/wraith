package proxy

import (
	"errors"
)

// clientHello is what wraith needs from a TLS ClientHello before deciding whether to
// decrypt a tunnel.
type clientHello struct {
	serverName string
	alpn       []string
}

var errNotClientHello = errors.New("not a TLS ClientHello")

// recordHeaderLen is the TLS record header: type, version, length.
const recordHeaderLen = 5

// helloRecordLen returns the length of the first TLS record from its 5-byte header, or an
// error if the bytes are not the start of a TLS handshake record.
func helloRecordLen(hdr []byte) (int, error) {
	if len(hdr) < recordHeaderLen || hdr[0] != 0x16 || hdr[1] != 0x03 {
		return 0, errNotClientHello
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n == 0 || n > 1<<14 {
		return 0, errNotClientHello
	}
	return n, nil
}

// parseClientHello reads the server name and ALPN list from one TLS record holding a
// ClientHello. Every length is checked; untrusted input never panics (fuzzed, S5.4).
func parseClientHello(rec []byte) (clientHello, error) {
	var h clientHello
	n, err := helloRecordLen(rec)
	if err != nil || len(rec) < recordHeaderLen+n {
		return h, errNotClientHello
	}
	r := reader(rec[recordHeaderLen : recordHeaderLen+n])

	typ, ok := r.u8()
	if !ok || typ != 1 { // client_hello
		return h, errNotClientHello
	}
	body, ok := r.vec24()
	if !ok {
		return h, errNotClientHello // split across records: wraith passes it through
	}
	b := reader(body)
	if _, ok := b.take(2 + 32); !ok { // legacy_version, random
		return h, errNotClientHello
	}
	if _, ok := b.vec8(); !ok { // legacy_session_id
		return h, errNotClientHello
	}
	if _, ok := b.vec16(); !ok { // cipher_suites
		return h, errNotClientHello
	}
	if _, ok := b.vec8(); !ok { // legacy_compression_methods
		return h, errNotClientHello
	}
	if len(b) == 0 {
		return h, nil // no extensions
	}
	exts, ok := b.vec16()
	if !ok {
		return h, errNotClientHello
	}
	e := reader(exts)
	for len(e) > 0 {
		typ, ok1 := e.u16()
		data, ok2 := e.vec16()
		if !ok1 || !ok2 {
			return h, errNotClientHello
		}
		d := reader(data)
		switch typ {
		case 0: // server_name
			list, ok := d.vec16()
			if !ok {
				return h, errNotClientHello
			}
			l := reader(list)
			for len(l) > 0 {
				nameType, ok1 := l.u8()
				name, ok2 := l.vec16()
				if !ok1 || !ok2 {
					return h, errNotClientHello
				}
				if nameType == 0 && h.serverName == "" {
					h.serverName = string(name)
				}
			}
		case 16: // application_layer_protocol_negotiation
			list, ok := d.vec16()
			if !ok {
				return h, errNotClientHello
			}
			l := reader(list)
			for len(l) > 0 {
				p, ok := l.vec8()
				if !ok || len(p) == 0 {
					return h, errNotClientHello
				}
				h.alpn = append(h.alpn, string(p))
			}
		}
	}
	return h, nil
}

// reader is a byte slice consumed from the front; every method reports whether there
// were enough bytes.
type reader []byte

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || len(*r) < n {
		return nil, false
	}
	b := (*r)[:n]
	*r = (*r)[n:]
	return b, true
}

func (r *reader) u8() (int, bool) {
	b, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return int(b[0]), true
}

func (r *reader) u16() (int, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return int(b[0])<<8 | int(b[1]), true
}

func (r *reader) vec8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	return r.take(n)
}

func (r *reader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.take(n)
}

func (r *reader) vec24() ([]byte, bool) {
	b, ok := r.take(3)
	if !ok {
		return nil, false
	}
	return r.take(int(b[0])<<16 | int(b[1])<<8 | int(b[2]))
}
