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
