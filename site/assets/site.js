// Copy buttons, and the docs table of contents that follows the reader.
document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const text = btn.getAttribute("data-copy");
    const done = () => {
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = old), 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => {});
    }
  });
});

const links = Array.from(document.querySelectorAll(".toc a[href^='#']"));
if (links.length && "IntersectionObserver" in window) {
  const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
  const visible = new Set();
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => (e.isIntersecting ? visible.add(e.target.id) : visible.delete(e.target.id)));
      const first = links.map((a) => a.getAttribute("href").slice(1)).find((id) => visible.has(id));
      if (first) {
        links.forEach((a) => a.classList.remove("active"));
        byId.get(first).classList.add("active");
      }
    },
    { rootMargin: "-80px 0px -60% 0px" }
  );
  byId.forEach((_, id) => {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });
}

// The contents list folds on narrow screens and stays open on wide ones.
const toc = document.querySelector(".toc details");
if (toc) {
  const wide = window.matchMedia("(min-width: 901px)");
  const sync = () => { toc.open = wide.matches; };
  sync();
  wide.addEventListener("change", sync);
}

// The home page's live view: a new flow arrives every few seconds and the selection
// follows it, as in wraith. Nothing moves when the reader asks for less motion.
const live = document.getElementById("live-rows");
const still = window.matchMedia("(prefers-reduced-motion: reduce)");
if (live && !still.matches) {
  const count = document.getElementById("live-count");
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const pad = (s, n) => (s + " ".repeat(n)).slice(0, Math.max(n, s.length));
  const status = { "2": "t-ok", "3": "t-acc", "4": "t-warn", "5": "t-bad" };
  const method = { GET: "t-get", POST: "t-post" };
  const pool = [
    ["sim iPhone 17 · Shop", "200", "GET", "vpn", "https://api.shop.example", "/v2/cart"],
    ["device 192.168.0.23", "201", "POST", "vpn", "https://api.shop.example", "/v2/orders"],
    ["sim iPhone 17 · Shop", "304", "GET", "vpn", "https://cdn.shop.example", "/img/7.png"],
    ["device 192.168.0.23", "tun", "CONNECT", "vpn", "p117-caldav.icloud.com:443", "", "no_decrypt"],
    ["sim iPhone 17 · Shop", "200", "GET", "direct", "https://rates.partner.example", "/today"],
    ["device 192.168.0.23", "401", "GET", "vpn", "https://api.shop.example", "/v2/wallet"],
    ["sim iPad Air · Shop", "200", "POST", "vpn", "https://api.shop.example", "/v2/events"],
    ["device 192.168.0.23", "200", "GET", "vpn", "https://api.shop.example", "/v2/recs"],
  ];
  // The rows already on the page, as data, so the script redraws them the same way.
  const rows = [
    ["12:04:31", "sim iPhone 17 · Shop", "200", "GET", "vpn", "https://api.shop.example", "/v2/cart"],
    ["12:04:31", "sim iPhone 17 · Shop", "201", "POST", "vpn", "https://api.shop.example", "/v2/orders"],
    ["12:04:32", "device 192.168.0.23", "200", "GET", "vpn", "https://api.shop.example", "/v2/profile"],
    ["12:04:32", "device 192.168.0.23", "tun", "CONNECT", "vpn", "gateway.icloud.com:443", "", "no_decrypt"],
    ["12:04:32", "sim iPhone 17 · Shop", "200", "GET", "direct", "https://rates.partner.example", "/today"],
    ["12:04:33", "sim iPhone 17 · Shop", "404", "GET", "vpn", "https://cdn.shop.example", "/img/42.png"],
    ["12:04:34", "device 192.168.0.23", "503", "GET", "vpn", "https://api.shop.example", "/v2/recs"],
  ];
  const draw = ([t, src, st, m, route, host, path, why], selected, fresh) => {
    const cls = fresh ? "live-row new" : "live-row";
    if (selected) {
      const text = `${t} ${pad(src, 22)} ${st} ${pad(m, 7)} ${pad(route, 6)} ${host}${path}${why ? "  " + why : ""}`;
      return `<span class="${cls}"><span class="t-mark">▌</span><span class="t-sel">${esc(text)}</span>\n</span>`;
    }
    const stc = st === "tun" ? "t-dim" : status[st[0]] || "t-ok";
    const mm = method[m] ? `<span class="${method[m]}">${pad(m, 7)}</span>` : `<b>${pad(m, 7)}</b>`;
    const rc = route === "direct" ? "t-mag" : "t-dim";
    const w = why ? `  <span class="t-dim">${why}</span>` : "";
    return `<span class="${cls}"> <span class="t-dim">${t}</span> ${esc(pad(src, 22))} <span class="${stc}">${st}</span> ${mm} <span class="${rc}">${pad(route, 6)}</span> ${esc(host)}<span class="t-soft">${esc(path)}</span>${w}\n</span>`;
  };
  let clock = 12 * 3600 + 4 * 60 + 34;
  let next = 0;
  let flows = 214;
  const hhmmss = (n) => [n / 3600, (n / 60) % 60, n % 60].map((x) => String(Math.floor(x)).padStart(2, "0")).join(":");
  setInterval(() => {
    if (document.hidden) return;
    clock += 1 + Math.floor(Math.random() * 2);
    rows.push([hhmmss(clock), ...pool[next++ % pool.length]]);
    rows.shift();
    flows += 1;
    if (count) count.textContent = flows;
    live.innerHTML = rows.map((r, i) => draw(r, i === rows.length - 1, i === rows.length - 1)).join("");
  }, 2600);
}

// The packets in the connection diagram move with SMIL; stop them for less motion.
if (still.matches) document.querySelectorAll("svg.flow").forEach((svg) => svg.pauseAnimations && svg.pauseAnimations());
