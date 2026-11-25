package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// replayDrop are the request headers a resend does not copy: hop-by-hop headers, the
// proxy's own, and those the transport sets from the request itself.
var replayDrop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Te", "Trailer",
	"Upgrade", "Proxy-Authorization", "Proxy-Authenticate", "Content-Length", "Host"}

// Replay sends a captured request again, the way the proxy forwards one: through the
// same dialer and route (VPN or bypass), with the upstream certificate verified as
// usual (S2.3, S2.4). The result is recorded as a new flow, its source marked
// "replay", and returned. A tunnel, or a request whose body was cut at capture, cannot
// be sent again.
func (s *Server) Replay(ctx context.Context, f store.Flow) (store.Flow, error) {
	if s.opts.Store == nil {
		return store.Flow{}, errors.New("nothing is recorded")
	}
	if f.Kind != store.KindHTTP {
		return store.Flow{}, errors.New("a tunnel was not decrypted: there is no request to send again")
	}
	if f.ReqBody.Truncated || int64(len(f.ReqBody.Data)) < f.ReqBody.Size {
		return store.Flow{}, fmt.Errorf("its body was cut at %d bytes when captured; raise capture.max_body_bytes to resend it", len(f.ReqBody.Data))
	}
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return store.Flow{}, fmt.Errorf("%q is not a URL to send to", f.URL)
	}
	var body io.Reader
	if f.ReqBody.Size > 0 {
		body = bytes.NewReader(f.ReqBody.Data)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, f.Method, u.String(), body)
	if err != nil {
		return store.Flow{}, err
	}
	for k, vs := range f.ReqHeader {
		req.Header[k] = append([]string(nil), vs...)
	}
	for _, c := range req.Header.Values("Connection") { // and the headers it names
		for _, h := range strings.Split(c, ",") {
			req.Header.Del(strings.TrimSpace(h))
		}
	}
	for _, h := range replayDrop {
		req.Header.Del(h)
	}
	label := "replay"
	if f.Source != "" {
		label = "replay · " + f.Source
	}
	req = req.WithContext(context.WithValue(req.Context(), verdictKey{}, Verdict{InSource: true, Label: label}))
	host := u.Hostname()
	if u.Port() != "" {
		host = net.JoinHostPort(host, u.Port())
	}
	req = s.beginFlow(req, f.URL, host)
	fr := flowOf(req.Context())

	rt := s.rp.Transport
	if u.Scheme == "https" {
		rt = s.tlsRP.Transport
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		fr.failed(http.StatusBadGateway, s.routeName(host, true), err.Error())
	} else {
		fr.response(resp)
		_, _ = io.Copy(io.Discard, resp.Body) // the capture records the flow at the end
		_ = resp.Body.Close()
	}
	fr.mu.Lock()
	out := fr.f
	fr.mu.Unlock()
	return out, err
}
