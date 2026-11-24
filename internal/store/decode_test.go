package store

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
	"testing"
)

func compress(t *testing.T, enc string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "zlib":
		w = zlib.NewWriter(&buf)
	case "flate":
		w, _ = flate.NewWriter(&buf, flate.DefaultCompression)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeUndoesContentEncoding(t *testing.T) {
	plain := []byte(strings.Repeat(`{"ordem":"A04FBEEB","status":"ok"}`, 50))
	for _, tc := range []struct{ header, with string }{
		{"gzip", "gzip"}, {" GZIP ", "gzip"}, {"x-gzip", "gzip"}, {"deflate", "zlib"}, {"deflate", "flate"},
	} {
		z := compress(t, tc.with, plain)
		d := Decode(Body{Data: z, Size: int64(len(z))}, tc.header)
		if !bytes.Equal(d.Data, plain) || d.Partial || d.Err != "" || d.Encoding == "" {
			t.Errorf("%q (%s): got %d bytes, %+v", tc.header, tc.with, len(d.Data), Decoded{Encoding: d.Encoding, Partial: d.Partial, Err: d.Err})
		}
	}
}

func TestDecodeLeavesOtherBodiesAsStored(t *testing.T) {
	raw := []byte(`{"a":1}`)
	for _, enc := range []string{"", "identity"} {
		if d := Decode(Body{Data: raw, Size: 7}, enc); !bytes.Equal(d.Data, raw) || d.Encoding != "" || d.Err != "" {
			t.Errorf("%q: %+v", enc, d)
		}
	}
	if d := Decode(Body{Data: raw, Size: 7}, "br"); !bytes.Equal(d.Data, raw) || d.Err != "br is not decoded" {
		t.Errorf("br: %+v", d)
	}
	if d := Decode(Body{Data: raw, Size: 7}, "gzip"); !bytes.Equal(d.Data, raw) || d.Err == "" {
		t.Errorf("corrupt gzip: %+v", d)
	}
	if d := Decode(Body{}, "gzip"); len(d.Data) != 0 || d.Err != "" {
		t.Errorf("empty: %+v", d)
	}
}

func TestDecodeTruncatedBodyShowsItsStart(t *testing.T) {
	plain := make([]byte, 0, 200000)
	for i := 0; len(plain) < 200000; i++ {
		plain = append(plain, []byte(strings.Repeat("x", i%7)+"\n")...)
	}
	z := compress(t, "gzip", plain)
	cut := z[:len(z)/2]
	d := Decode(Body{Data: cut, Size: int64(len(z)), Truncated: true}, "gzip")
	if !d.Partial || d.Err != "" || len(d.Data) == 0 || !bytes.HasPrefix(plain, d.Data) {
		t.Fatalf("got %d bytes, partial %v, err %q", len(d.Data), d.Partial, d.Err)
	}
}

func TestDecodeIsCapped(t *testing.T) {
	z := compress(t, "gzip", make([]byte, MaxDecoded+1000))
	d := Decode(Body{Data: z, Size: int64(len(z))}, "gzip")
	if len(d.Data) != MaxDecoded || !d.Partial {
		t.Fatalf("got %d bytes, partial %v", len(d.Data), d.Partial)
	}
}
