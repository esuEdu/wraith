package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// wsFrame encodes one frame; a client's are masked.
func wsFrame(fin bool, op byte, payload []byte, mask, rsv1 bool) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}
	out := []byte{b0}
	var m byte
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 1<<16:
		out = append(out, m|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, m|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if !mask {
		return append(out, payload...)
	}
	key := [4]byte{0x12, 0x34, 0x56, 0x78}
	out = append(out, key[:]...)
	for i, c := range payload {
		out = append(out, c^key[i%4])
	}
	return out
}

func readWSFrame(r *bufio.Reader) (op byte, payload []byte, err error) {
	h := make([]byte, 2)
	if _, err = io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(r, b[:])
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(r, b[:])
		n = int64(binary.BigEndian.Uint64(b[:]))
	}
	var key [4]byte
	if h[1]&0x80 != 0 {
		_, _ = io.ReadFull(r, key[:])
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if h[1]&0x80 != 0 {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return h[0] & 0x0f, payload, nil
}

// wsEcho answers the WebSocket handshake, echoes the client's first text message, then
// closes.
func wsEcho(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
		_ = brw.Flush()
		var msg []byte
		for {
			op, p, err := readWSFrame(brw.Reader)
			if err != nil {
				return
			}
			if op == 9 { // ping
				_, _ = conn.Write(wsFrame(true, 10, p, false, false))
				continue
			}
			msg = append(msg, p...)
			if len(msg) >= len("hello world") { // both frames of the message
				break
			}
		}
		_, _ = conn.Write(wsFrame(true, 1, append([]byte("echo: "), msg...), false, false))
		_, _ = conn.Write(wsFrame(true, 8, append([]byte{0x03, 0xe8}, "bye"...), false, false))
		_, _, _ = readWSFrame(brw.Reader) // the client's close
	}
}

// talk opens a WebSocket on conn (to the proxy, or a TLS session through it) and has
// the exchange wsEcho expects: "hello world" in two frames with a ping between them.
func talk(t *testing.T, conn net.Conn, target, host string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", target, host)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	var out []byte
	out = append(out, wsFrame(false, 1, []byte("hello "), true, false)...)
	out = append(out, wsFrame(true, 9, []byte("p"), true, false)...)
	out = append(out, wsFrame(true, 0, []byte("world"), true, false)...)
	for _, b := range out { // a byte at a time: the tap must not care how bytes arrive
		if _, err := conn.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	for {
		op, p, err := readWSFrame(br)
		if err != nil {
			t.Fatal(err)
		}
		if op == 1 && string(p) != "echo: hello world" {
			t.Fatalf("echo %q", p)
		}
		if op == 8 {
			_, _ = conn.Write(wsFrame(true, 8, p, true, false))
			return
		}
	}
}

// wantMessages checks each direction's messages, in order; the two directions are read
// side by side, so how they interleave is up to timing.
func wantMessages(t *testing.T, f store.Flow) {
	t.Helper()
	got := map[bool][]string{}
	for _, m := range f.Messages {
		got[m.FromClient] = append(got[m.FromClient], m.Op+":"+string(m.Data))
	}
	sent := []string{"ping:p", "text:hello world", "close:\x03\xe8bye"}
	received := []string{"pong:p", "text:echo: hello world", "close:\x03\xe8bye"}
	if strings.Join(got[true], "|") != strings.Join(sent, "|") || strings.Join(got[false], "|") != strings.Join(received, "|") {
		t.Fatalf("sent %q\nreceived %q", got[true], got[false])
	}
}

func TestWebSocketMessagesAreRecorded(t *testing.T) {
	ts := httptest.NewServer(wsEcho(t))
	t.Cleanup(ts.Close)
	st := store.New(100, 1<<20)
	_, addr := startProxy(t, Options{Store: st})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	talk(t, conn, ts.URL+"/live", strings.TrimPrefix(ts.URL, "http://"))
	f := waitMessages(t, st, 6)
	if f.Status != 101 || f.URL != ts.URL+"/live" {
		t.Fatalf("flow %+v", f)
	}
	wantMessages(t, f)
}

func TestWebSocketMessagesAreRecordedWhenDecrypted(t *testing.T) {
	ts := httptest.NewTLSServer(wsEcho(t))
	t.Cleanup(ts.Close)
	e := startMITM(t, poolOf(ts.Certificate()), nil)
	host := strings.TrimPrefix(ts.URL, "https://")
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	tc := tls.Client(&bufConn{Conn: conn, r: br}, &tls.Config{RootCAs: poolOf(e.ca.Certificate()), ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	talk(t, tc, "/live", host)
	f := waitMessages(t, e.store, 6)
	if f.URL != "https://"+host+"/live" {
		t.Fatalf("flow %+v", f)
	}
	wantMessages(t, f)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func waitMessages(t *testing.T, st *store.Store, n int) store.Flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, f := range st.Flows() {
			if f.Status == 101 && len(f.Messages) >= n {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no WebSocket with %d messages: %+v", n, st.Flows())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// deflated compresses messages one after another as permessage-deflate does with
// context takeover: one stream, flushed after each, the 00 00 ff ff tail cut off.
func deflated(t *testing.T, msgs ...string) [][]byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	var out [][]byte
	for _, m := range msgs {
		buf.Reset()
		_, _ = w.Write([]byte(m))
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		out = append(out, bytes.TrimSuffix(bytes.Clone(buf.Bytes()), []byte{0, 0, 0xff, 0xff}))
	}
	return out
}

func TestWebSocketParserReadsCompressedAndLargeMessages(t *testing.T) {
	var got []store.Message
	p := &wsParser{emit: func(m store.Message) { got = append(got, m) }, deflate: true, takeover: true}
	repeat := strings.Repeat(`{"price": 42, "currency": "BRL"} `, 20)
	z := deflated(t, repeat, repeat) // the second leans on the first: context takeover
	big := bytes.Repeat([]byte("a"), 70_000)
	var stream []byte
	stream = append(stream, wsFrame(true, 1, z[0], false, true)...)
	stream = append(stream, wsFrame(true, 1, z[1], false, true)...)
	stream = append(stream, wsFrame(true, 2, big, false, false)...)
	stream = append(stream, wsFrame(true, 1, []byte("plain"), false, false)...)
	for len(stream) > 0 { // in uneven pieces
		n := min(len(stream), 7)
		p.feed(stream[:n])
		stream = stream[n:]
	}
	if len(got) != 4 {
		t.Fatalf("%d messages: %+v", len(got), got)
	}
	for i := range 2 {
		if string(got[i].Data) != repeat || got[i].Note != "" || got[i].Size != int64(len(repeat)) {
			t.Fatalf("compressed message %d: %q (%s)", i, got[i].Data, got[i].Note)
		}
	}
	if b := got[2]; b.Op != "binary" || b.Size != 70_000 || len(b.Data) != wsKeep || !b.Truncated {
		t.Fatalf("big message: op %s size %d kept %d", b.Op, b.Size, len(b.Data))
	}
	if string(got[3].Data) != "plain" {
		t.Fatalf("after a big message: %q", got[3].Data)
	}

	// Garbage stops the parser rather than making up messages.
	got = nil
	p = &wsParser{emit: func(m store.Message) { got = append(got, m) }}
	p.feed([]byte{0x83, 0x00, 0x81, 0x01, 'x'})
	if len(got) != 0 || !p.bad {
		t.Fatalf("reserved opcode: %+v", got)
	}
}

func FuzzWebSocketParser(f *testing.F) {
	f.Add(wsFrame(true, 1, []byte("hi"), true, false))
	f.Add(append(wsFrame(false, 2, []byte("ab"), false, false), wsFrame(true, 0, []byte("cd"), false, false)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := &wsParser{emit: func(store.Message) {}, deflate: true, takeover: true}
		p.feed(b)
	})
}
