package store

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
)

// MaxDecoded caps what Decode expands a body to, so a small compressed body cannot
// become a huge one in memory.
const MaxDecoded = 16 << 20

// Decoded is a body with its Content-Encoding undone, for showing and exporting only:
// the proxy always forwards bodies exactly as they were sent.
type Decoded struct {
	Data     []byte
	Encoding string // the encoding that was undone; "" when the body was not encoded
	Partial  bool   // Data is only the start: the stored body was truncated, or hit MaxDecoded
	Err      string // why the body was left as stored, e.g. an encoding wraith cannot undo
}

// Decode undoes contentEncoding (the Content-Encoding header) on b. gzip and deflate are
// supported; for anything else, or a body that fails to decode, Data is b.Data as stored
// and Err says why.
func Decode(b Body, contentEncoding string) Decoded {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" || len(b.Data) == 0 {
		return Decoded{Data: b.Data, Partial: b.Truncated}
	}
	raw := Decoded{Data: b.Data, Partial: b.Truncated}
	var r io.Reader
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b.Data))
		if err != nil {
			raw.Err = enc + " body could not be decoded"
			return raw
		}
		r = zr
	case "deflate":
		// "deflate" is zlib-wrapped by the spec, but some servers send raw deflate.
		if zr, err := zlib.NewReader(bytes.NewReader(b.Data)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(b.Data))
		}
	default:
		raw.Err = enc + " is not decoded"
		return raw
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDecoded+1))
	d := Decoded{Data: data, Encoding: enc}
	switch {
	case len(data) > MaxDecoded:
		d.Data, d.Partial = data[:MaxDecoded], true
	case err == nil:
	case b.Truncated && errors.Is(err, io.ErrUnexpectedEOF):
		d.Partial = true // the stored bytes stop mid-stream: show what they hold
	default:
		raw.Err = enc + " body could not be decoded"
		return raw
	}
	return d
}
