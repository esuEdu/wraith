package proxy

import (
	"html/template"
	"net"
	"net/http"
)

// serveOwn answers requests addressed to wraith itself rather than proxied: the setup
// page a device opens from the QR code, and the CA certificate (S2.6). It reports whether
// it answered. A device that opens the page with the right key is allowed from then on.
func (s *Server) serveOwn(w http.ResponseWriter, r *http.Request, peer net.IP, access Access) bool {
	if s.opts.Unlock == nil && s.opts.CACert == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	switch r.URL.Path {
	case "/ca", "/ca.pem":
		if s.opts.CACert == nil {
			return false
		}
		if access != Allowed {
			http.Error(w, "scan the QR code in wraith's window first", http.StatusForbidden)
			return true
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="wraith-ca.pem"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(s.opts.CACert)
		return true
	case "/":
		if key := r.URL.Query().Get("key"); key != "" && access != Allowed && peer != nil && s.opts.Unlock != nil {
			if s.opts.Unlock(peer, key, r.UserAgent()) {
				access = Allowed
			}
		}
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			host, port = r.Host, "80"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = setupPage.Execute(w, struct {
			Allowed, CA bool
			Host, Port  string
		}{access == Allowed, s.opts.CACert != nil, host, port})
		return true
	}
	return false
}

var setupPage = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wraith</title>
<style>
body{font:17px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:24px;background:#14101f;color:#dcd2ee}
h1{font-size:28px;color:#c980f2;margin:0 0 4px}
.step{background:#211a33;border-radius:14px;padding:14px 16px;margin:14px 0}
.n{color:#c980f2;font-weight:700;margin-right:6px}
a.button{display:block;text-align:center;padding:14px;border-radius:12px;background:#c980f2;color:#14101f;font-weight:600;text-decoration:none;margin:12px 0 4px}
.v{font:600 20px ui-monospace,Menlo,monospace;color:#72e0aa;user-select:all}
.muted{color:#b6abd0;font-size:15px}
</style></head><body>
<h1>wraith</h1>
{{if .Allowed}}
<p class="muted">This device is allowed, and remembered for next time.</p>
{{if .CA}}<div class="step"><span class="n">1</span>Download the certificate, then tap <b>Allow</b>.
<a class="button" href="/ca">Download the certificate</a></div>
<div class="step"><span class="n">2</span>Open <b>Settings</b>, tap <b>Profile Downloaded</b> and <b>Install</b>. Then in <b>General › About › Certificate Trust Settings</b>, turn on <b>wraith CA</b>. Steps 1 and 2 are needed once per device.</div>
{{end}}<div class="step"><span class="n">{{if .CA}}3{{else}}1{{end}}</span>In <b>Settings › Wi-Fi</b>, tap ⓘ next to your network, then <b>Configure Proxy › Manual</b>:
<p>Server <span class="v">{{.Host}}</span><br>Port <span class="v">{{.Port}}</span></p></div>
<p class="muted">Set Configure Proxy back to Off when wraith is not running, or this device loses its connection.</p>
{{else}}
<p>To use wraith from this device, scan the QR code in wraith's window on the Mac with the Camera.</p>
{{end}}
</body></html>`))
