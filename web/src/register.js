import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { API, b64, esc, errorMessage, hasIdentity, saveIdentity, handshake, initServerInfo } from "./common.js";

const logEl = document.getElementById("log");
const stepsEl = document.getElementById("steps");
const resultEl = document.getElementById("result");
const registerBtn = document.getElementById("register-btn");

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

registerBtn.addEventListener("click", async () => {
  const accountId = document.getElementById("account-id").value.trim();
  const password = document.getElementById("password").value;
  const confirm2 = document.getElementById("password2").value;
  if (!accountId) return;

  logEl.innerHTML = "";
  resultEl.classList.remove("visible");
  for (const el of stepsEl.children) el.classList.remove("active", "done", "error");
  registerBtn.disabled = true;

  try {


    if (password !== confirm2) throw new Error("Passwords do not match.");
    if (password.length < 10) throw new Error("Password must be at least 10 characters.");

    if (hasIdentity(accountId)) {
      const proceed = confirm(
        `This browser already has a local identity for "${accountId}". ` +
          `Continuing will generate a NEW keypair and overwrite it -- the old key stops working. Continue?`
      );
      if (!proceed) {
        registerBtn.disabled = false;
        return;
      }
    }

    setPhase("keygen");
    const sigKp = ml_dsa65.keygen();
    log("1a", "Generate ML-DSA-65 identity keypair", `public key ${sigKp.publicKey.length} bytes &mdash; proves who you are`);


    const kemKp = ml_kem768.keygen();
    log("1b", "Generate ML-KEM-768 encryption keypair", `public key ${kemKp.publicKey.length} bytes &mdash; opens your files; secret half never leaves this browser`);
    markDone("keygen");


    setPhase("enroll");
    const enrollRes = await fetch(`${API}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        account_id: accountId,
        password,
        sig_public_key_b64: b64(sigKp.publicKey),
        kem_public_key_b64: b64(kemKp.publicKey),
      }),
    });
    if (!enrollRes.ok) {
      const err = await enrollRes.json().catch(() => ({}));
      throw new Error(
        enrollRes.status === 409
          ? `Account "${accountId}" is already taken. Pick a different id — existing accounts can't be re-registered.`
          : errorMessage(err, enrollRes.status)
      );
    }
    const enrollJson = await enrollRes.json();
    log("2a", "Register with auth service", `<span class="pill ok">${esc(enrollJson.status)}</span> account=<code>${esc(enrollJson.account_id)}</code> &middot; password hashed with Argon2id server-side`);

    await saveIdentity(accountId, password, sigKp, kemKp);
    log("2b", "Seal both secret keys locally", `encrypted with a PBKDF2 key derived from your password &mdash; a stolen browser profile alone cannot open them`);
    markDone("enroll");

    setPhase("session");
    const auth = await handshake(accountId, password, sigKp, log);
    markDone("session");

    document.getElementById("result-account").textContent = accountId;
    document.getElementById("result-scope").textContent = auth.scope.join(", ");
    resultEl.classList.add("visible");
  } catch (err) {
    log("!", "Registration halted", esc(err.message || err), "error");
    document.querySelector(".active")?.classList.add("error");
  } finally {
    registerBtn.disabled = false;
  }
});

initServerInfo();
