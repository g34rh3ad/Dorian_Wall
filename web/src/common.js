import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

export const API = "";


export function errorMessage(body, fallbackStatus) {
  const d = body && body.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return d
      .map((e) => {
        const field = Array.isArray(e.loc) ? e.loc[e.loc.length - 1] : "input";
        return `${field}: ${e.msg || "invalid"}`;
      })
      .join("; ");
  }
  return `request failed (${fallbackStatus})`;
}

export function esc(value) {
  return String(value ?? "").replace(/[&<>"'`=/]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
    "'": "&#39;", "`": "&#96;", "=": "&#61;", "/": "&#47;",
  }[c]));
}

export function b64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}


const KEY_WRAP_INFO = "quantum-auth-drive|file-key-wrap|v1";

async function kdfFromSharedSecret(sharedSecret) {
  const base = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(KEY_WRAP_INFO),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}


export async function wrapFileKeyFor(recipientKemPublicKey, fileKey) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientKemPublicKey);
  const aes = await kdfFromSharedSecret(sharedSecret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, fileKey)
  );


  const wrapped = new Uint8Array(nonce.length + sealed.length);
  wrapped.set(nonce, 0);
  wrapped.set(sealed, nonce.length);
  return { kemCiphertext: cipherText, wrappedKey: wrapped };
}


export async function unwrapFileKey(kemSecretKey, kemCiphertext, wrappedKey) {
  const sharedSecret = ml_kem768.decapsulate(kemCiphertext, kemSecretKey);
  const aes = await kdfFromSharedSecret(sharedSecret);
  const nonce = wrappedKey.slice(0, 12);
  const sealed = wrappedKey.slice(12);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, aes, sealed)
  );
}

export function newFileKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}


export async function encryptFile(fileKey, plaintext) {
  const aes = await crypto.subtle.importKey("raw", fileKey, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, plaintext)
  );
  const out = new Uint8Array(nonce.length + sealed.length);
  out.set(nonce, 0);
  out.set(sealed, nonce.length);
  return out;
}

export async function decryptFile(fileKey, blob) {
  const aes = await crypto.subtle.importKey("raw", fileKey, "AES-GCM", false, ["decrypt"]);
  const nonce = blob.slice(0, 12);
  const sealed = blob.slice(12);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, aes, sealed)
  );
}


const IDENTITY_PREFIX = "qad:identity:";
const VAULT_ITERATIONS = 600000;


async function vaultKey(password, salt) {
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: VAULT_ITERATIONS },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function saveIdentity(accountId, password, sigKeypair, kemKeypair) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aes = await vaultKey(password, salt);
  const secrets = JSON.stringify({
    sigSecret: b64(sigKeypair.secretKey),
    kemSecret: b64(kemKeypair.secretKey),
  });
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce }, aes, new TextEncoder().encode(secrets)
    )
  );
  localStorage.setItem(IDENTITY_PREFIX + accountId, JSON.stringify({
    v: 2,
    salt: b64(salt),
    nonce: b64(nonce),
    sealed: b64(sealed),


    sigPublic: b64(sigKeypair.publicKey),
    kemPublic: b64(kemKeypair.publicKey),
  }));
}

export async function loadIdentity(accountId, password) {
  const raw = localStorage.getItem(IDENTITY_PREFIX + accountId);
  if (!raw) return null;
  const v = JSON.parse(raw);
  if (v.v !== 2) {
    throw new Error(
      "This browser holds an old-format identity from before end-to-end " +
      "encryption. Register again to create a new one."
    );
  }
  const aes = await vaultKey(password, unb64(v.salt));
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(v.nonce) }, aes, unb64(v.sealed)
    );
  } catch {

    throw new Error("Incorrect password for this device's stored keys.");
  }
  const secrets = JSON.parse(new TextDecoder().decode(plain));
  return {
    sig: { publicKey: unb64(v.sigPublic), secretKey: unb64(secrets.sigSecret) },
    kem: { publicKey: unb64(v.kemPublic), secretKey: unb64(secrets.kemSecret) },
  };
}

export function hasIdentity(accountId) {
  return localStorage.getItem(IDENTITY_PREFIX + accountId) !== null;
}


export async function handshake(accountId, password, sigKeypair, log) {
  const kemKp = ml_kem768.keygen();
  log("3", "Generate ephemeral ML-KEM-768 keypair", `public key ${kemKp.publicKey.length} bytes &middot; fresh for this session`);

  const initRes = await fetch(`${API}/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ account_id: accountId, kem_public_key_b64: b64(kemKp.publicKey) }),
  });
  if (!initRes.ok) {
    const err = await initRes.json().catch(() => ({}));
    throw new Error(errorMessage(err, initRes.status));
  }
  const init = await initRes.json();
  const ciphertext = unb64(init.ciphertext_b64);
  const challenge = unb64(init.challenge_b64);
  log("4", "Server encapsulates + sends challenge", `session=<code>${init.session_id.slice(0, 8)}&hellip;</code> ciphertext ${ciphertext.length}B &middot; challenge ${challenge.length}B`);

  const sharedSecret = ml_kem768.decapsulate(ciphertext, kemKp.secretKey);
  log("5", "Decapsulate shared secret locally", `${sharedSecret.length} bytes &middot; matches the server's without ever crossing the network`);

  const signature = ml_dsa65.sign(challenge, sigKeypair.secretKey);
  log("6", "Sign server's challenge", `ML-DSA-65 signature, ${signature.length} bytes &mdash; factor 2: proves this device holds the enrolled secret key`);


  const authRes = await fetch(`${API}/session/auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: init.session_id,
      password,
      signature_b64: b64(signature),
    }),
  });
  if (!authRes.ok) {
    const err = await authRes.json().catch(() => ({}));
    throw new Error(errorMessage(err, authRes.status));
  }
  const auth = await authRes.json();
  log(
    "7",
    "Server verifies both factors + issues token",
    `server session-key fingerprint <code>${auth.session_key_fingerprint}</code> &mdash; derived from the shared secret mixed with server-side QRNG entropy`
  );
  log("8", "Token received", `<code class="token">${auth.token.slice(0, 48)}&hellip;</code> &middot; scope ${auth.scope.join(", ")} &middot; TTL 10 min &middot; recorded by hash in the sessions table`);

  return auth;
}

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
export function fmtTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

export function initServerInfo() {
  fetch(`${API}/`)
    .then((r) => r.json())
    .then((info) => {
      const el = document.getElementById("server-info");
      if (el) el.textContent = `${info.kem_alg} · ${info.sig_alg}`;
    })
    .catch(() => {
      const el = document.getElementById("server-info");
      if (el) el.textContent = "server unreachable";
    });
}
