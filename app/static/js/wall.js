const MAX         = 280;
const VISIBLE_MAX = 6;

/* ── Compose counter ── */
const textarea = document.getElementById("compose-text");
const counter  = document.getElementById("char-count");
const postBtn  = document.getElementById("post-btn");

textarea.addEventListener("input", () => {
  const len = textarea.value.length;
  counter.textContent = `${len} / ${MAX}`;
  counter.className = "char-count" +
    (len > MAX ? " over" : len >= MAX - 20 ? " warn" : "");
  postBtn.disabled = len === 0 || len > MAX;
});

/* ── Read more / Read less ── */
document.querySelectorAll("[data-post-body]").forEach(body => {
  if (body.scrollHeight <= body.clientHeight) return;
  const btn = document.createElement("button");
  btn.className = "read-more";
  btn.textContent = "Read more";
  body.after(btn);
  btn.addEventListener("click", () => {
    const collapsed = body.classList.toggle("collapsed");
    btn.textContent = collapsed ? "Read more" : "Read less";
  });
});

/* ── Group circles ── */
const container = document.getElementById("group-circles");

function initials(username) {
  return username.slice(0, 2).toUpperCase();
}

function renderCircles() {
  container.innerHTML = "";
  const visible   = members.slice(0, VISIBLE_MAX);
  const overflow  = members.length - VISIBLE_MAX;
  const canRemove = members.length > 1;

  visible.forEach(m => {
    const el = document.createElement("div");
    el.className = "circle" + (canRemove ? " removable" : "");
    el.title = m.username;
    el.textContent = initials(m.username);

    if (canRemove) {
      const x = document.createElement("span");
      x.className = "circle-remove";
      x.textContent = "✕";
      el.appendChild(x);
      el.addEventListener("click", () => removeMember(m.id));
    }
    container.appendChild(el);
  });

  if (overflow > 0) {
    const el = document.createElement("div");
    el.className = "circle overflow";
    el.title = members.slice(VISIBLE_MAX).map(m => m.username).join("\n");
    el.textContent = `+${overflow}`;
    container.appendChild(el);
  }

  container.appendChild(makeAddButton());
}

const PLUS_SVG = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="7" y1="1" x2="7" y2="13"/><line x1="1" y1="7" x2="13" y2="7"/></svg>`;

function makeAddButton() {
  const btn = document.createElement("div");
  btn.className = "circle add-btn";
  btn.title = "Add member";
  btn.innerHTML = PLUS_SVG;
  btn.addEventListener("click", () => showAddInput(btn));
  return btn;
}

function showAddInput(addBtn) {
  addBtn.replaceWith(makeInputWidget());
}

function makeInputWidget() {
  const wrap  = document.createElement("div");
  wrap.className = "add-input-wrap";
  const input = document.createElement("input");
  input.type        = "text";
  input.placeholder = "Username";
  input.autofocus   = true;
  wrap.appendChild(input);

  setTimeout(() => input.focus(), 0);

  input.addEventListener("blur", () => setTimeout(renderCircles, 150));

  input.addEventListener("keydown", async e => {
    if (e.key === "Escape") { renderCircles(); return; }
    if (e.key !== "Enter")  return;
    const username = input.value.trim();
    if (!username) return;

    const res = await fetch("/group/add", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username }),
    });

    if (res.status === 401) { window.location.href = "/login"; return; }

    if (!res.ok) {
      input.classList.remove("shake");
      void input.offsetWidth;
      input.classList.add("shake");
      input.addEventListener("animationend", () => input.classList.remove("shake"), { once: true });
      return;
    }

    const member = await res.json();
    members.push(member);
    renderCircles();
  });

  return wrap;
}

async function removeMember(userId) {
  const res = await fetch(`/group/remove/${userId}`, { method: "POST" });
  if (!res.ok) return;
  if (userId === CURRENT_ID) {
    location.reload();
  } else {
    members = members.filter(m => m.id !== userId);
    renderCircles();
  }
}

renderCircles();