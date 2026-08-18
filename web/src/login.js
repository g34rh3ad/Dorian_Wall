import {
  API, esc, loadIdentity, hasIdentity, handshake, fmtBytes, fmtTime, initServerInfo,
  newFileKey, encryptFile, decryptFile, wrapFileKeyFor, unwrapFileKey, unb64, b64,
} from "./common.js";

const $ = (id) => document.getElementById(id);
const logEl = $("log");
const stepsEl = $("steps");
const bodyEl = $("drive-body");

let session = null;


let view = "mine";
let rows = { mine: [], shared: [] };
let selected = new Set();


function log(step, title, detail, cls = "") {
  const row = document.createElement("div");
  row.className = "log-row" + (cls ? " " + cls : "");
  row.innerHTML = `<span class="step-num">${step}</span><div class="step-body"><div class="step-title">${title}</div><div class="step-detail">${detail}</div></div>`;
  logEl.appendChild(row);
  logEl.scrollTop = logEl.scrollHeight;
}
const setPhase = (p) => [...stepsEl.children].forEach((el) => el.classList.toggle("active", el.dataset.phase === p));
const markDone = (p) => document.querySelector(`[data-phase="${p}"]`)?.classList.add("done");

$("login-btn").addEventListener("click", async () => {
  const accountId = $("account-id").value.trim();
  const password = $("password").value;
  if (!accountId || !password) return;

  logEl.innerHTML = "";
  [...stepsEl.children].forEach((el) => el.classList.remove("active", "done", "error"));
  $("login-btn").disabled = true;

  try {
    setPhase("identity");
    if (!hasIdentity(accountId)) {
      throw new Error(`No local identity for "${accountId}" on this device. Register first.`);
    }


    const identity = await loadIdentity(accountId, password);
    log("1", "Unlock device keys", `PBKDF2-derived key opened the local vault &mdash; ML-DSA (identity) + ML-KEM (file decryption)`);
    markDone("identity");

    setPhase("session");
    const auth = await handshake(accountId, password, identity.sig, log);
    session = { accountId, token: auth.token, scope: auth.scope, kem: identity.kem };
    $("password").value = "";
    markDone("session");
    markDone("access");

    enterDrive();
  } catch (err) {
    log("!", "Sign-in halted", esc(err.message || err), "error");
    document.querySelector(".active")?.classList.add("error");
  } finally {
    $("login-btn").disabled = false;
  }
});

function enterDrive() {
  $("drive-account").textContent = session.accountId;
  $("avatar").textContent = session.accountId[0].toUpperCase();
  $("drive-role").textContent = session.scope.includes("admin") ? "administrator" : "signed in";
  $("log-slot").appendChild(logEl);
  $("signin-view").hidden = true;
  $("drive-view").hidden = false;
  refresh();
}

$("signout-btn").addEventListener("click", async () => {


  if (session) {
    await fetch(`${API}/session/logout`, { method: "POST", headers: authHeaders() }).catch(() => {});
  }
  session = null;
  selected.clear();
  rows = { mine: [], shared: [] };
  $("drive-view").hidden = true;
  $("signin-view").hidden = false;
  $("signin-view").prepend(logEl);
  logEl.innerHTML = "";
  [...stepsEl.children].forEach((el) => el.classList.remove("active", "done", "error"));
});


const authHeaders = () => ({ Authorization: `Bearer ${session.token}` });

async function refresh() {
  const [mineRes, sharedRes] = await Promise.all([
    fetch(`${API}/drive/files`, { headers: authHeaders() }),
    fetch(`${API}/drive/shared`, { headers: authHeaders() }),
  ]);
  rows.mine = (await mineRes.json()).files;
  rows.shared = (await sharedRes.json()).files;

  $("count-mine").textContent = rows.mine.length;
  $("count-shared").textContent = rows.shared.length;

  const used = rows.mine.reduce((n, f) => n + f.size, 0);
  const QUOTA = 25 * 1024 * 1024;
  $("storage-val").textContent = fmtBytes(used);
  $("storage-bar").style.width = `${Math.min(100, (used / QUOTA) * 100)}%`;

  selected.clear();
  render();
}


const EXT_CLASS = {
  txt: "doc", md: "doc", pdf: "pdf", doc: "doc", docx: "doc",
  png: "img", jpg: "img", jpeg: "img", gif: "img", svg: "img", webp: "img",
  zip: "arc", tar: "arc", gz: "arc", "7z": "arc",
  mp4: "vid", mov: "vid", mp3: "vid", wav: "vid",
  js: "code", py: "code", json: "code", html: "code", css: "code", sh: "code",
};
function fileIcon(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const kind = EXT_CLASS[ext] || "gen";
  return `<span class="fico ${kind}">${esc((ext || "?").slice(0, 4))}</span>`;
}

function render() {
  const list = rows[view];
  const isMine = view === "mine";

  $("crumb-label").textContent = isMine ? "My Drive" : "Shared with me";
  $("th-owner").textContent = isMine ? "Shared" : "Owner";

  bodyEl.innerHTML = list.length
    ? list
        .map((f) => {
          const badge = isMine
            ? f.shared_with_count
              ? `<span class="pill ok">${f.shared_with_count} recipient${f.shared_with_count > 1 ? "s" : ""}</span>`
              : `<span class="dash">&mdash;</span>`
            : `<span class="pill">${esc(f.owner)}</span>`;
          return `
        <tr data-id="${f.file_id}" class="${selected.has(f.file_id) ? "sel" : ""}">
          <td class="c-check"><input type="checkbox" class="row-check" data-id="${f.file_id}" ${selected.has(f.file_id) ? "checked" : ""} aria-label="Select ${esc(f.filename)}" /></td>
          <td class="c-name">${fileIcon(f.filename)}<span class="fname">${esc(f.filename)}</span></td>
          <td class="c-owner">${badge}</td>
          <td class="c-size num">${fmtBytes(f.size)}</td>
          <td class="c-date">${fmtTime(isMine ? f.created : f.shared_at)}</td>
        </tr>`;
        })
        .join("")
    : `<tr class="empty-row"><td colspan="5">${
        isMine ? "No files yet — use Upload to add one." : "Nothing has been shared with you."
      }</td></tr>`;

  bodyEl.querySelectorAll(".row-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      cb.checked ? selected.add(cb.dataset.id) : selected.delete(cb.dataset.id);
      syncSelectionUI();
    });
  });
  bodyEl.querySelectorAll("tr[data-id]").forEach((tr) => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("input")) return;
      const cb = tr.querySelector(".row-check");
      cb.checked = !cb.checked;
      cb.dispatchEvent(new Event("change"));
    });
  });

  syncSelectionUI();
}

function syncSelectionUI() {
  const list = rows[view];
  bodyEl.querySelectorAll("tr[data-id]").forEach((tr) => tr.classList.toggle("sel", selected.has(tr.dataset.id)));

  const n = selected.size;
  $("download-btn").disabled = n === 0;


  $("share-btn").disabled = !(n === 1 && view === "mine");
  $("delete-btn").disabled = !(n > 0 && view === "mine");
  $("check-all").checked = n > 0 && n === list.length;
  $("check-all").indeterminate = n > 0 && n < list.length;

  $("foot-count").textContent = `${list.length} item${list.length === 1 ? "" : "s"}`;
  $("foot-sel").textContent = n ? `${n} selected` : "";

  if (n !== 1) hideSharePanel();
}

$("check-all").addEventListener("change", (e) => {
  selected.clear();
  if (e.target.checked) rows[view].forEach((f) => selected.add(f.file_id));
  render();
});

document.querySelectorAll(".side-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".side-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    view = btn.dataset.view;
    selected.clear();
    hideSharePanel();
    render();
  });
});

$("refresh-btn").addEventListener("click", refresh);


$("upload-btn").addEventListener("click", () => $("file-input").click());

$("file-input").addEventListener("change", async () => {
  const file = $("file-input").files[0];
  if (!file) return;
  const btn = $("upload-btn");
  btn.disabled = true;
  btn.textContent = "Uploading…";
  try {
    btn.textContent = "Encrypting…";

    const plaintext = new Uint8Array(await file.arrayBuffer());
    const fileKey = newFileKey();
    const ciphertext = await encryptFile(fileKey, plaintext);


    const { kemCiphertext, wrappedKey } = await wrapFileKeyFor(session.kem.publicKey, fileKey);
    fileKey.fill(0);

    btn.textContent = "Uploading…";
    const form = new FormData();
    form.append("file", new Blob([ciphertext], { type: "application/octet-stream" }), "blob");
    form.append("filename", file.name);
    form.append("content_type", file.type || "application/octet-stream");
    form.append("kem_ciphertext_b64", b64(kemCiphertext));
    form.append("wrapped_key_b64", b64(wrappedKey));

    const res = await fetch(`${API}/drive/upload`, { method: "POST", headers: authHeaders(), body: form });
    if (!res.ok) throw new Error((await res.json()).detail || res.status);
    if (view !== "mine") document.querySelector('.side-item[data-view="mine"]').click();
    await refresh();
  } catch (err) {
    alert(`Upload failed: ${err.message || err}`);
  } finally {
    $("file-input").value = "";
    btn.disabled = false;
    btn.innerHTML = "&#8593; Upload";
  }
});

$("download-btn").addEventListener("click", async () => {
  for (const id of selected) {
    const f = rows[view].find((x) => x.file_id === id);
    if (f) await downloadFile(id, f.filename);
  }
});

$("delete-btn").addEventListener("click", async () => {
  const targets = rows.mine.filter((f) => selected.has(f.file_id));
  if (!targets.length) return;

  const shared = targets.filter((f) => f.shared_with_count).length;
  const what = targets.length === 1 ? `"${targets[0].filename}"` : `${targets.length} files`;
  const warn = shared ? `\n\n${shared} of these are shared — recipients will lose access too.` : "";
  if (!confirm(`Delete ${what}? This cannot be undone.${warn}`)) return;

  const btn = $("delete-btn");
  btn.disabled = true;
  const failed = [];
  for (const f of targets) {
    const res = await fetch(`${API}/drive/files/${f.file_id}`, { method: "DELETE", headers: authHeaders() });
    if (!res.ok) failed.push(f.filename);
  }
  await refresh();
  if (failed.length) alert(`Could not delete: ${failed.join(", ")}`);
});

async function downloadFile(fileId, filename) {


  const [res, keyRes] = await Promise.all([
    fetch(`${API}/drive/files/${fileId}`, { headers: authHeaders() }),
    fetch(`${API}/drive/files/${fileId}/key`, { headers: authHeaders() }),
  ]);
  if (!res.ok) {
    alert(`Download rejected (${res.status})`);
    return;
  }
  if (!keyRes.ok) {
    alert("No decryption key for this file on this account.");
    return;
  }

  const grant = await keyRes.json();
  const fileKey = await unwrapFileKey(
    session.kem.secretKey,
    unb64(grant.kem_ciphertext_b64),
    unb64(grant.wrapped_key_b64)
  );
  const ciphertext = new Uint8Array(await res.arrayBuffer());
  let plaintext;
  try {
    plaintext = await decryptFile(fileKey, ciphertext);
  } catch {
    alert("Decryption failed — the file or its key grant may be corrupt.");
    return;
  } finally {
    fileKey.fill(0);
  }

  const url = URL.createObjectURL(new Blob([plaintext]));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}


const panel = $("share-panel");
const hideSharePanel = () => { panel.hidden = true; };

$("share-btn").addEventListener("click", async () => {
  if (panel.hidden === false) return hideSharePanel();
  await renderSharePanel([...selected][0]);
});

async function renderSharePanel(fileId) {
  const f = rows.mine.find((x) => x.file_id === fileId);
  if (!f) return;
  const { shares } = await (await fetch(`${API}/drive/files/${fileId}/shares`, { headers: authHeaders() })).json();

  panel.innerHTML = `
    <div class="sp-head">
      <span class="sp-title">Share <strong>${esc(f.filename)}</strong></span>
      <button class="sp-close" aria-label="Close">&times;</button>
    </div>
    <div class="sp-add">
      <input type="text" class="share-input" id="sp-input" placeholder="account id" spellcheck="false" />
      <button class="tb primary" id="sp-go">Grant read access</button>
      <span class="share-msg" id="sp-msg"></span>
    </div>
    ${
      shares.length
        ? `<div class="sp-list">${shares
            .map(
              (s) => `<div class="share-row">
                <span class="share-who">${esc(s.shared_with)}</span>
                <span class="file-meta">since ${fmtTime(s.created)}</span>
                <button class="revoke-btn" data-acct="${esc(s.shared_with)}">Revoke</button>
              </div>`
            )
            .join("")}</div>`
        : `<div class="share-empty">Not shared with anyone yet.</div>`
    }
    <div class="sp-note">End-to-end: the file key was re-wrapped in your browser to this account's public key. The server stores the grant but cannot open it.</div>`;
  panel.hidden = false;

  panel.querySelector(".sp-close").addEventListener("click", hideSharePanel);
  panel.querySelector("#sp-go").addEventListener("click", () => grant(fileId));
  panel.querySelector("#sp-input").addEventListener("keydown", (e) => { if (e.key === "Enter") grant(fileId); });
  panel.querySelectorAll(".revoke-btn").forEach((b) =>
    b.addEventListener("click", async () => {
      await fetch(`${API}/drive/files/${fileId}/share/${encodeURIComponent(b.dataset.acct)}`, {
        method: "DELETE", headers: authHeaders(),
      });
      const keep = new Set(selected);
      await refresh();
      selected = keep;
      render();
      await renderSharePanel(fileId);
    })
  );
}

async function grant(fileId) {
  const input = panel.querySelector("#sp-input");
  const msg = panel.querySelector("#sp-msg");
  const target = input.value.trim();
  if (!target) return;

  msg.textContent = "re-wrapping key…";
  msg.className = "share-msg";


  const pkRes = await fetch(`${API}/accounts/${encodeURIComponent(target)}/kem-key`, {
    headers: authHeaders(),
  });
  if (!pkRes.ok) {
    msg.textContent = pkRes.status === 404 ? `no such account "${target}"` : `failed (${pkRes.status})`;
    msg.className = "share-msg err";
    return;
  }
  const recipientPk = unb64((await pkRes.json()).kem_public_key_b64);

  const myGrantRes = await fetch(`${API}/drive/files/${fileId}/key`, { headers: authHeaders() });
  if (!myGrantRes.ok) {
    msg.textContent = "you have no key for this file";
    msg.className = "share-msg err";
    return;
  }
  const myGrant = await myGrantRes.json();
  const fileKey = await unwrapFileKey(
    session.kem.secretKey,
    unb64(myGrant.kem_ciphertext_b64),
    unb64(myGrant.wrapped_key_b64)
  );
  const { kemCiphertext, wrappedKey } = await wrapFileKeyFor(recipientPk, fileKey);
  fileKey.fill(0);

  const res = await fetch(`${API}/drive/files/${fileId}/share`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({
      account_id: target,
      kem_ciphertext_b64: b64(kemCiphertext),
      wrapped_key_b64: b64(wrappedKey),
    }),
  });
  if (!res.ok) {
    msg.textContent = (await res.json().catch(() => ({}))).detail || `failed (${res.status})`;
    msg.className = "share-msg err";
    return;
  }
  const keep = new Set(selected);
  await refresh();
  selected = keep;
  render();
  await renderSharePanel(fileId);
}

initServerInfo();
