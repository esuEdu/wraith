// Spike M0.1: can we tell which process opened a proxied connection?
//
// Runs a minimal pass-through proxy on 127.0.0.1:9090. For each connection it
// finds the client's PID from its local port (via lsof), walks the parent
// chain (via ps) and reports whether the process belongs to an iOS Simulator
// (an ancestor named launchd_sim). Throwaway code: the real resolver will use
// libproc through cgo.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type proc struct {
	pid  int
	ppid int
	path string
}

type source struct {
	chain     []proc
	simulator bool
	simArgs   string
}

func main() {
	addr := flag.String("listen", "127.0.0.1:9090", "address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("spike proxy on %s; point an app or the Mac's proxy settings here", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	start := time.Now()
	port := c.RemoteAddr().(*net.TCPAddr).Port
	src, err := identify(port)
	took := time.Since(start)

	br := bufio.NewReader(c)
	req, rerr := http.ReadRequest(br)
	if rerr != nil {
		return
	}
	label := describe(src, err)
	log.Printf("%-60s %s %s  (lookup %s)", label, req.Method, req.Host, took.Round(time.Millisecond))

	if req.Method == http.MethodConnect {
		up, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
		if err != nil {
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(up, br)
		io.Copy(c, up)
		return
	}

	req.RequestURI = ""
	tr := &http.Transport{Proxy: nil}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Write(c)
}

// identify finds the process that owns the client side of the connection.
func identify(clientPort int) (source, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+strconv.Itoa(clientPort), "-sTCP:ESTABLISHED", "-Fp").Output()
	if err != nil {
		return source{}, fmt.Errorf("lsof: %w", err)
	}
	self := os.Getpid()
	pid := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			p, _ := strconv.Atoi(line[1:])
			if p != self {
				pid = p
				break
			}
		}
	}
	if pid == 0 {
		return source{}, fmt.Errorf("no owner found for port %d", clientPort)
	}

	var s source
	for pid > 1 && len(s.chain) < 32 {
		p, err := psInfo(pid)
		if err != nil {
			break
		}
		s.chain = append(s.chain, p)
		if filepath.Base(p.path) == "launchd_sim" {
			s.simulator = true
			if args, err := exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output(); err == nil {
				s.simArgs = strings.TrimSpace(string(args))
			}
			break
		}
		pid = p.ppid
	}
	return s, nil
}

func psInfo(pid int) (proc, error) {
	out, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return proc{}, err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return proc{}, fmt.Errorf("unexpected ps output %q", out)
	}
	ppid, _ := strconv.Atoi(fields[0])
	return proc{pid: pid, ppid: ppid, path: strings.Join(fields[1:], " ")}, nil
}

func describe(s source, err error) string {
	if err != nil {
		return "[unknown: " + err.Error() + "]"
	}
	if len(s.chain) == 0 {
		return "[unknown]"
	}
	leaf := s.chain[0]
	kind := "mac"
	if s.simulator {
		kind = "SIMULATOR"
	}
	label := fmt.Sprintf("[%s pid=%d %s]", kind, leaf.pid, filepath.Base(leaf.path))
	if s.simulator && os.Getenv("SPIKE_VERBOSE") != "" {
		label += "\n    path: " + leaf.path + "\n    launchd_sim: " + s.simArgs
	}
	return label
}
