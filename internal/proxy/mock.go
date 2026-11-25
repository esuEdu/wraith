package proxy

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/esuEdu/wraith/internal/store"
)

// A mock answers a request of the capture source itself, without asking the upstream:
// to see an error screen, or a feature the backend does not have yet. Options.Mock
// picks one per request; only decrypted (or plain http) requests can be mocked.

// MockResponse is what a mock answers.
type MockResponse struct {
	Rule   string // the rule that matched, shown on the flow
	Status int
	Header http.Header
	Body   []byte
	Delay  time.Duration // before answering
	Err    string        // why the mock could not be read; it answers 502 with this
}

// mock answers r with the mock Options.Mock picks for it, if any, and reports whether it
// did. url is the request's full URL, as recorded.
func (s *Server) mock(w http.ResponseWriter, r *http.Request, url string) bool {
	if s.opts.Mock == nil || !verdictOf(r.Context()).InSource {
		return false
	}
	m := s.opts.Mock(r.Method, url)
	if m == nil {
		return false
	}
	if m.Err != "" {
		m.Status, m.Header, m.Body = http.StatusBadGateway, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte("wraith: "+m.Err+"\n")
	}
	if m.Status == 0 {
		m.Status = http.StatusOK
	}
	// The request body is read, so it is recorded, as the upstream would have read it.
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<20))
		_ = r.Body.Close()
	}
	if err := sleep(r.Context(), m.Delay); err != nil {
		return true
	}
	h := w.Header()
	for k, vs := range m.Header {
		h[k] = append([]string(nil), vs...)
	}
	h.Del("Content-Encoding") // the body is sent as it is written
	h.Set("Content-Length", strconv.Itoa(len(m.Body)))
	w.WriteHeader(m.Status)
	if r.Method != http.MethodHead && m.Status != http.StatusNoContent && m.Status != http.StatusNotModified {
		_, _ = w.Write(m.Body)
	}

	if fr := flowOf(r.Context()); fr != nil {
		body := m.Body
		if limit := s.opts.Store.MaxBody(); int64(len(body)) > limit {
			body = body[:limit]
		}
		fr.mu.Lock()
		fr.f.Status, fr.f.Route, fr.f.Mock, fr.f.Err, fr.f.Throttle = m.Status, "mock", m.Rule, m.Err, ""
		fr.f.RespHeader = h.Clone()
		fr.f.RespBody = store.Body{Data: body, Size: int64(len(m.Body)), Truncated: len(body) < len(m.Body)}
		fr.mu.Unlock()
		fr.commit()
	}
	return true
}
