package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// A WebSocket inside the source is recorded as its upgrade request (status 101) and then
// its messages, added to that flow as they pass. wsTap sits on the upstream side of the
// upgraded connection: what the app sends is written to it, what the server sends is
// read from it. It only watches: every byte passes on unchanged.

const (
	wsKeep           = 64 << 10 // payload bytes kept per message
	wsKeepCompressed = 1 << 20  // compressed bytes kept, to decompress the message
	wsMaxInflated    = 8 << 20  // the most one message is decompressed to
)

// tapWebSocket wraps an upgraded connection's body so its messages are recorded in fr.
func tapWebSocket(rwc io.ReadWriteCloser, fr *flowRec, h http.Header) io.ReadWriteCloser {
	ext := strings.ToLower(strings.Join(h.Values("Sec-WebSocket-Extensions"), ","))
	deflate := strings.Contains(ext, "permessage-deflate")
	newParser := func(fromClient bool, noTakeover string) *wsParser {
		return &wsParser{fromClient: fromClient, emit: fr.addMessage, deflate: deflate,
			takeover: deflate && !strings.Contains(ext, noTakeover)}
	}
	return &wsTap{ReadWriteCloser: rwc,
		fromServer: newParser(false, "server_no_context_takeover"),
		fromClient: newParser(true, "client_no_context_takeover")}
}

type wsTap struct {
	io.ReadWriteCloser
	fromServer, fromClient *wsParser
}

func (t *wsTap) Read(p []byte) (int, error) {
	n, err := t.ReadWriteCloser.Read(p)
	t.fromServer.feed(p[:n])
	return n, err
}

func (t *wsTap) Write(p []byte) (int, error) {
	n, err := t.ReadWriteCloser.Write(p)
	t.fromClient.feed(p[:n])
	return n, err
}

// addMessage adds a message to the recorded flow, letting the oldest go past
// store.MaxMessages. Each change makes a new slice: copies already handed out share
// the old one.
func (fr *flowRec) addMessage(m store.Message) {
	fr.mu.Lock()
	id := fr.f.ID
	fr.mu.Unlock()
	if id == 0 {
		return
	}
	fr.s.opts.Store.Update(id, func(f *store.Flow) {
		old := f.Messages
		if len(old) >= store.MaxMessages {
			old = old[len(old)-store.MaxMessages+1:]
			f.MessagesDropped++
		}
		msgs := make([]store.Message, len(old), len(old)+1)
		copy(msgs, old)
		f.Messages = append(msgs, m)
	})
}

// wsParser reads one direction's frames (RFC 6455) from the bytes as they pass, in
// whatever pieces they come.
type wsParser struct {
	fromClient bool
	emit       func(store.Message)

	hdr       []byte // the frame header so far
	inPayload bool
	left      int64 // payload bytes still to come in this frame
	mask      [4]byte
	masked    bool
	off       int64 // payload bytes of this frame seen, for unmasking
	op        byte
	fin, rsv1 bool

	msg *wsMessage // the data message being put together from its frames
	ctl *wsMessage // the control frame being read (ping, pong, close)

	deflate, takeover bool   // permessage-deflate; with context takeover
	window            []byte // the last 32 KiB this direction decompressed to
	broken            bool   // a message could not be decompressed; later ones cannot either
	bad               bool   // not WebSocket framing: stop reading
}

type wsMessage struct {
	at         time.Time
	op         byte
	compressed bool
	data       []byte
	size       int64
	cut        bool
}

func (p *wsParser) feed(b []byte) {
	for len(b) > 0 && !p.bad {
		if !p.inPayload {
			b = p.header(b)
			continue
		}
		n := int64(len(b))
		if n > p.left {
			n = p.left
		}
		p.payload(b[:n])
		b = b[n:]
		p.left -= n
		if p.left == 0 {
			p.frameDone()
		}
	}
}

// header gathers the frame header from b and returns the rest of b.
func (p *wsParser) header(b []byte) []byte {
	need := 2
	for {
		if len(p.hdr) >= 2 {
			need = 2
			switch p.hdr[1] & 0x7f {
			case 126:
				need += 2
			case 127:
				need += 8
			}
			if p.hdr[1]&0x80 != 0 {
				need += 4
			}
		}
		if len(p.hdr) >= need || len(b) == 0 {
			break
		}
		take := min(need-len(p.hdr), len(b))
		p.hdr = append(p.hdr, b[:take]...)
		b = b[take:]
	}
	if len(p.hdr) < need {
		return b
	}
	h := p.hdr
	p.hdr = p.hdr[:0]
	p.fin, p.rsv1, p.op = h[0]&0x80 != 0, h[0]&0x40 != 0, h[0]&0x0f
	p.masked = h[1]&0x80 != 0
	i := 2
	switch n := h[1] & 0x7f; n {
	case 126:
		p.left = int64(binary.BigEndian.Uint16(h[2:4]))
		i = 4
	case 127:
		p.left = int64(h[2] & 0x7f) // the top bit is 0 by the RFC
		for _, c := range h[3:10] {
			p.left = p.left<<8 | int64(c)
		}
		i = 10
	default:
		p.left = int64(n)
	}
	if p.masked {
		copy(p.mask[:], h[i:i+4])
	}
	p.off = 0
	switch {
	case p.op >= 8: // control
		if p.op > 10 || p.left > 125 {
			p.bad = true
			return nil
		}
		p.ctl = &wsMessage{at: time.Now(), op: p.op}
	case p.op == 1 || p.op == 2:
		p.msg = &wsMessage{at: time.Now(), op: p.op, compressed: p.deflate && p.rsv1}
	case p.op != 0:
		p.bad = true // reserved opcodes: this is not a WebSocket we understand
		return nil
	}
	p.inPayload = true
	if p.left == 0 {
		p.frameDone()
	}
	return b
}

// payload keeps what fits of b, unmasked, in the message it belongs to.
func (p *wsParser) payload(b []byte) {
	m := p.msg
	if p.op >= 8 {
		m = p.ctl
	}
	if m == nil {
		p.off += int64(len(b))
		return
	}
	m.size += int64(len(b))
	keep := wsKeep
	if m.compressed {
		keep = wsKeepCompressed
	}
	room := keep - len(m.data)
	if room < len(b) {
		m.cut = true
	}
	start := len(m.data)
	m.data = append(m.data, b[:max(min(room, len(b)), 0)]...)
	if p.masked {
		for i := start; i < len(m.data); i++ {
			m.data[i] ^= p.mask[(p.off+int64(i-start))%4]
		}
	}
	p.off += int64(len(b))
}

func (p *wsParser) frameDone() {
	p.inPayload = false
	if p.op >= 8 {
		if m := p.ctl; m != nil {
			p.send(m, "")
		}
		p.ctl = nil
		return
	}
	if p.fin && p.msg != nil {
		m := p.msg
		p.msg = nil
		note := ""
		if m.compressed {
			note = p.inflate(m)
		}
		if note != "" {
			m.data = nil // compressed bytes mean nothing on screen
		}
		p.send(m, note)
	}
}

// inflate decompresses a permessage-deflate message in place (RFC 7692), with the
// direction's earlier output as the dictionary when the context is taken over. It
// returns why it could not.
func (p *wsParser) inflate(m *wsMessage) string {
	if p.broken {
		return "compressed; not decoded (an earlier message was too big to follow)"
	}
	if m.cut {
		p.broken = p.takeover
		return "compressed; too big to decode"
	}
	src := io.MultiReader(bytes.NewReader(m.data), bytes.NewReader([]byte{0, 0, 0xff, 0xff}))
	var dict []byte
	if p.takeover {
		dict = p.window
	}
	r := flate.NewReaderDict(src, dict)
	out, err := io.ReadAll(io.LimitReader(r, wsMaxInflated+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) || len(out) > wsMaxInflated {
		p.broken = p.takeover
		return "compressed; not decoded"
	}
	if p.takeover {
		p.window = append(p.window, out...)
		if over := len(p.window) - 32<<10; over > 0 {
			p.window = append([]byte(nil), p.window[over:]...)
		}
	}
	m.size = int64(len(out))
	m.cut = len(out) > wsKeep
	m.data = out[:min(len(out), wsKeep)]
	return ""
}

var wsOps = map[byte]string{1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}

func (p *wsParser) send(m *wsMessage, note string) {
	p.emit(store.Message{At: m.at, FromClient: p.fromClient, Op: wsOps[m.op],
		Data: bytes.Clone(m.data), Size: m.size, Truncated: m.cut, Note: note})
}
