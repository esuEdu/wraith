package export

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/esuEdu/wraith/internal/store"
	"github.com/esuEdu/wraith/internal/version"
)

// HAR 1.2 (http://www.softwareishard.com/blog/har-12-spec/), the parts wraith fills.
type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
	Comment string     `json:"comment,omitempty"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
	Comment         string      `json:"comment,omitempty"`
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Cookies     []harNV      `json:"cookies"`
	Headers     []harNV      `json:"headers"`
	QueryString []harNV      `json:"queryString"`
	PostData    *harPostData `json:"postData,omitempty"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int64        `json:"bodySize"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNV    `json:"cookies"`
	Headers     []harNV    `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int64      `json:"bodySize"`
}

type harContent struct {
	Size        int64  `json:"size"`
	Compression int64  `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HAR renders the HTTP flows as a HAR 1.2 document; tunnels, which carry no request
// that wraith saw, are counted in the log comment instead. Truncated bodies and each
// flow's source and route are noted in entry comments.
func HAR(flows []store.Flow, r Redactor) ([]byte, error) {
	doc := harFile{Log: harLog{
		Version: "1.2",
		Creator: harCreator{Name: "wraith", Version: version.Version},
		Entries: []harEntry{},
	}}
	tunnels := 0
	for _, f := range flows {
		if f.Kind != store.KindHTTP {
			tunnels++
			continue
		}
		doc.Log.Entries = append(doc.Log.Entries, harEntryFor(f, r))
	}
	if tunnels > 0 {
		doc.Log.Comment = fmt.Sprintf("%d tunnel(s) passed through without decrypting are not included", tunnels)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func harEntryFor(f store.Flow, r Redactor) harEntry {
	ms := float64(f.Duration.Microseconds()) / 1000
	u := r.URL(f.URL)
	e := harEntry{
		StartedDateTime: f.Start.UTC().Format(time.RFC3339Nano),
		Time:            ms,
		Request: harRequest{
			Method: f.Method, URL: u, HTTPVersion: f.Proto,
			Cookies: []harNV{}, Headers: nvs(r.Header(f.ReqHeader)), QueryString: query(u),
			HeadersSize: -1, BodySize: f.ReqBody.Size,
		},
		Response: harResponse{
			Status: f.Status, StatusText: http.StatusText(f.Status), HTTPVersion: f.Proto,
			Cookies: []harNV{}, Headers: nvs(r.Header(f.RespHeader)), HeadersSize: -1, BodySize: f.RespBody.Size,
			Content: harContent{Size: f.RespBody.Size, MimeType: f.RespHeader.Get("Content-Type")},
		},
		Timings: harTimings{Wait: ms},
	}
	var notes []string
	// HAR holds bodies decoded; the Content-Encoding header stays to say how they were sent.
	decode := func(what string, b store.Body, h http.Header) store.Decoded {
		d := store.Decode(b, h.Get("Content-Encoding"))
		if d.Err != "" {
			notes = append(notes, what+" body left as sent: "+d.Err)
		}
		return d
	}
	if f.ReqBody.Size > 0 {
		d := decode("request", f.ReqBody, f.ReqHeader)
		text, enc := bodyText(d.Data)
		e.Request.PostData = &harPostData{MimeType: f.ReqHeader.Get("Content-Type"), Text: text, Encoding: enc}
	}
	resp := decode("response", f.RespBody, f.RespHeader)
	e.Response.Content.Text, e.Response.Content.Encoding = bodyText(resp.Data)
	if resp.Encoding != "" && !resp.Partial {
		e.Response.Content.Size = int64(len(resp.Data))
		e.Response.Content.Compression = e.Response.Content.Size - f.RespBody.Size
	}

	if f.Source != "" {
		notes = append(notes, "source: "+f.Source)
	}
	if f.Route != "" {
		notes = append(notes, "route: "+f.Route)
	}
	if f.ReqBody.Truncated {
		notes = append(notes, fmt.Sprintf("request body truncated to %d of %d bytes", len(f.ReqBody.Data), f.ReqBody.Size))
	}
	if f.RespBody.Truncated {
		notes = append(notes, fmt.Sprintf("response body truncated to %d of %d bytes", len(f.RespBody.Data), f.RespBody.Size))
	}
	if f.Err != "" {
		notes = append(notes, "error: "+f.Err)
	}
	e.Comment = strings.Join(notes, "; ")
	return e
}

func bodyText(b []byte) (text, encoding string) {
	if len(b) == 0 {
		return "", ""
	}
	if utf8.Valid(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func nvs(h http.Header) []harNV {
	out := []harNV{}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, harNV{Name: k, Value: v})
		}
	}
	return out
}

func query(u string) []harNV {
	out := []harNV{}
	parsed, err := url.Parse(u)
	if err != nil {
		return out
	}
	q := parsed.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range q[k] {
			out = append(out, harNV{Name: k, Value: v})
		}
	}
	return out
}

// ErrExists means the export target exists and force was not given (S3.2).
var ErrExists = errors.New("file exists; use --force to overwrite it")

// WriteFile writes an export with mode 0600, refusing to replace an existing file
// unless force is set (S3.2).
func WriteFile(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- a path the user named
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s: %w", path, ErrExists)
	}
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // an existing file overwritten with --force
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
