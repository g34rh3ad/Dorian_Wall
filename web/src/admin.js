import { API, esc, loadIdentity, hasIdentity, handshake, fmtBytes, fmtTime, initServerInfo } from "./common.js";

const logEl = document.getElementById("log");
const stepsEl = document.getElementById("steps");
const deniedPanel = document.getElementById("denied-panel");
const dashboard = document.getElementById("dashboard");
const loginBtn = document.getElementById("login-btn");
const accountsBody = document.getElementById("accounts-body");
const filesBody = document.getElementById("files-body");

let token = null;

function log(step, title, detail, cls = "") {
  const row = document.createElement("div");
  row.className = "log-row" + (cls ? " " + cls : "");
  row.innerHTML = `<span class="step-num">${step}</span><div class="step-body"><div class="step-title">${title}</div><div class="step-detail">${detail}</div></div>`;
  logEl.appendChild(row);
  logEl.scrollTop = logEl.scrollHeight;
}
function setPhase(phase) {
  for (const el of stepsEl.children) el.classList.toggle("active", el.dataset.phase === phase);
}
function markDone(phase) {
  document.querySelector(`[data-phase="${phase}"]`)?.classList.add("done");
}

function splitBytes(n) {
  if (n < 1024) return [String(n), "B"];
  if (n < 1024 * 1024) return [(n / 1024).toFixed(1), "KB"];
  return [(n / (1024 * 1024)).toFixed(1), "MB"];
}

async function loadDashboard() {
  const headers = { Authorization: `Bearer ${token}` };
  const [accountsRes, filesRes, statsRes] = await Promise.all([
    fetch(`${API}/admin/accounts`, { headers }),
    fetch(`${API}/admin/files`, { headers }),
    fetch(`${API}/admin/stats`, { headers }),
  ]);
  const accounts = (await accountsRes.json()).accounts;
  const files = (await filesRes.json()).files;
  const stats = await statsRes.json();


  const [val, unit] = splitBytes(stats.total_bytes);
  document.getElementById("t-accounts").textContent = stats.accounts;
  document.getElementById("t-accounts-sub").textContent =
    `${stats.admins} admin${stats.admins === 1 ? "" : "s"}`;
  document.getElementById("t-files").textContent = stats.files;
  document.getElementById("t-storage").textContent = val;
  document.getElementById("t-storage-unit").textContent = unit;
  document.getElementById("t-shares").textContent = stats.shares;
  document.getElementById("t-sessions").textContent = stats.active_sessions;


  accountsBody.innerHTML = accounts.length
    ? accounts
        .map(
          (a) => `
      <tr>
        <td class="owner">${esc(a.account_id)}</td>
        <td>${a.is_admin ? '<span class="pill admin">admin</span>' : '<span class="pill">user</span>'}</td>
        <td>${fmtTime(a.enrolled_at)}</td>
        <td class="num">${a.file_count}</td>
        <td class="num">${fmtBytes(a.total_bytes)}</td>
      </tr>`
        )
        .join("")
    : `<tr class="empty-row"><td colspan="5">No accounts yet.</td></tr>`;


  const users = accounts.filter((a) => a.total_bytes > 0).slice(0, 8);
  const max = Math.max(1, ...users.map((a) => a.total_bytes));
  document.getElementById("storage-bars").innerHTML = users.length
    ? users
        .map(
          (a) => `
      <div class="bar-row">
        <span class="bar-name" title="${esc(a.account_id)}">${esc(a.account_id)}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(a.total_bytes / max) * 100}%"></span></span>
        <span class="bar-val">${fmtBytes(a.total_bytes)}</span>
      </div>`
        )
        .join("")
    : `<div class="share-empty">No files stored yet.</div>`;


  filesBody.innerHTML = files.length
    ? files
        .map(
          (f) => `
      <tr>
        <td class="owner">${esc(f.owner)}</td>
        <td>${esc(f.filename)}</td>
        <td class="num">${fmtBytes(f.size)}</td>
        <td>${fmtTime(f.created)}</td>
        <td class="num"><button class="del-btn" data-id="${f.file_id}">Delete</button></td>
      </tr>`
        )
        .join("")
    : `<tr class="empty-row"><td colspan="5">No files uploaded yet.</td></tr>`;

  filesBody.querySelectorAll(".del-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this file? This removes it for its owner too.")) return;
      await fetch(`${API}/admin/files/${btn.dataset.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      await loadDashboard();
    });
  });
}

loginBtn.addEventListener("click", async () => {
  const accountId = document.getElementById("account-id").value.trim();
  const password = document.getElementById("password").value;
  if (!accountId || !password) return;

  logEl.innerHTML = "";
  deniedPanel.classList.remove("visible");
  dashboard.classList.remove("visible");
  for (const el of stepsEl.children) el.classList.remove("active", "done", "error");
  loginBtn.disabled = true;

  try {
    setPhase("identity");
    if (!hasIdentity(accountId)) {
      throw new Error(`No local identity for "${accountId}" on this device/browser. Register first.`);
    }
    const identity = await loadIdentity(accountId, password);
    log("1", "Unlock device keys", `PBKDF2-derived key opened the local vault for &quot;${esc(accountId)}&quot;`);
    markDone("identity");

    setPhase("session");
    const auth = await handshake(accountId, password, identity.sig, log);
    markDone("session");

    setPhase("check");
    if (!auth.scope.includes("admin")) {
      log("!", "Access denied", `token scope is <code>${esc(auth.scope.join(", "))}</code> &mdash; no <code>admin</code> scope granted to this account`, "error");
      deniedPanel.classList.add("visible");
      return;
    }
    log("9", "Admin scope confirmed", `<span class="pill admin">admin</span> granted &mdash; account was promoted via <code>promote_admin.py</code>`);
    markDone("check");

    token = auth.token;
    await loadDashboard();
    dashboard.classList.add("visible");
  } catch (err) {
    log("!", "Sign-in halted", esc(err.message || err), "error");
    document.querySelector(".active")?.classList.add("error");
  } finally {
    loginBtn.disabled = false;
  }
});

function tickClock() {
  const el = document.getElementById("clock");
  if (el) el.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
tickClock();
setInterval(tickClock, 10000);

initServerInfo();
