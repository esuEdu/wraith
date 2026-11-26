package source

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/esuEdu/wraith/internal/execx"
)

// pcblist_n is a stream of records, each starting with its length and kind. For every TCP
// connection the kernel writes an XSO_INPCB record (ports) followed by an XSO_SOCKET
// record (owning PIDs). Offsets below were measured on macOS 27 against connections with
// known ports and PIDs; recordSize guards them, and a mismatch falls back to lsof. Since
// macOS 27.2 the list holds only the calling process's own sockets (same layout), so a
// client's socket is missing from it and lsof answers instead (Resolver.ownerOf).
const (
	kindSocket = 0x001
	kindInpcb  = 0x010

	recordSize = 104 // xinpcb_n and xsocket_n

	inpcbFport = 16 // u16, network byte order
	inpcbLport = 18

	socketLastPID = 68 // so_last_pid, int32
	socketEPID    = 72 // so_e_pid: the process a socket was delegated for, or 0
)

var errLayout = errors.New("unexpected net.inet.tcp.pcblist_n layout")

// ownerFromPCBList returns the PID owning the TCP socket whose local port is lport and
// foreign port fport. A socket delegated to another process (so_e_pid) belongs to it.
func ownerFromPCBList(lport, fport int) (int, error) {
	buf, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return 0, err
	}
	return parsePCBList(buf, lport, fport)
}

func parsePCBList(buf []byte, lport, fport int) (int, error) {
	le := binary.LittleEndian
	if len(buf) < 4 {
		return 0, errLayout
	}
	off := align8(int(le.Uint32(buf))) // skip the xinpgen header
	matched := false
	for off+8 <= len(buf) {
		n := int(le.Uint32(buf[off:]))
		kind := le.Uint32(buf[off+4:])
		if n < 8 || off+n > len(buf) {
			break // the trailing xinpgen, or the end
		}
		rec := buf[off : off+n]
		switch kind {
		case kindInpcb:
			if n != recordSize {
				return 0, errLayout
			}
			matched = int(binary.BigEndian.Uint16(rec[inpcbLport:])) == lport &&
				int(binary.BigEndian.Uint16(rec[inpcbFport:])) == fport
		case kindSocket:
			if matched {
				if n != recordSize {
					return 0, errLayout
				}
				if epid := pidAt(rec, socketEPID); epid > 0 {
					return epid, nil
				}
				if pid := pidAt(rec, socketLastPID); pid > 0 {
					return pid, nil
				}
				return 0, ErrUnknown
			}
		}
		off += align8(n)
	}
	return 0, ErrUnknown
}

func align8(n int) int { return (n + 7) &^ 7 }

// pidAt reads a pid_t; anything outside 1..MaxInt32 is "no process".
func pidAt(rec []byte, off int) int {
	v := binary.LittleEndian.Uint32(rec[off:])
	if v == 0 || v > math.MaxInt32 {
		return 0
	}
	return int(v)
}

// ownerFromLsof is the slow fallback (30 to 80 ms): for a kernel whose layout changed, or
// one that lists only the caller's own sockets.
func ownerFromLsof(ctx context.Context, run execx.Runner, lport, fport, self int) (int, error) {
	out, err := run.Run(ctx, "lsof", "-nP", "-iTCP:"+strconv.Itoa(lport), "-sTCP:ESTABLISHED", "-Fpn")
	if err != nil {
		return 0, ErrUnknown // lsof exits 1 when nothing matches
	}
	pid := 0
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "p"):
			pid, _ = strconv.Atoi(line[1:])
		case strings.HasPrefix(line, "n") && pid > 0 && pid != self:
			// n127.0.0.1:52000->127.0.0.1:9090: the client side ends with our port.
			if strings.HasSuffix(line, ":"+strconv.Itoa(fport)) && strings.Contains(line, ":"+strconv.Itoa(lport)+"->") {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: lsof found no owner for port %d", ErrUnknown, lport)
}
