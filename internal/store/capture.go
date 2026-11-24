package store

import (
	"io"
	"sync"
)

// Capture wraps a body as it streams through the proxy: every byte passes on unchanged,
// the first max bytes are kept, and done runs once, when the body ends or is closed,
// with what was captured.
type Capture struct {
	rc   io.ReadCloser
	max  int64
	body Body
	once sync.Once
	done func(Body)
}

// NewCapture wraps rc. A nil rc is treated as an empty body.
func NewCapture(rc io.ReadCloser, max int64, done func(Body)) *Capture {
	if rc == nil {
		rc = io.NopCloser(eofReader{})
	}
	return &Capture{rc: rc, max: max, done: done}
}

func (c *Capture) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.body.Size += int64(n)
		if room := c.max - int64(len(c.body.Data)); room > 0 {
			keep := min(int64(n), room)
			c.body.Data = append(c.body.Data, p[:keep]...)
			if keep < int64(n) {
				c.body.Truncated = true
			}
		} else {
			c.body.Truncated = true
		}
	}
	if err == io.EOF {
		c.finish()
	}
	return n, err
}

// Close closes the body and finishes the capture.
func (c *Capture) Close() error {
	err := c.rc.Close()
	c.finish()
	return err
}

func (c *Capture) finish() {
	c.once.Do(func() {
		if c.done != nil {
			c.done(c.body)
		}
	})
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
