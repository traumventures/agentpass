// WebAuthn glue for the agentpass web UI. Passkeys are used only for their
// PRF extension output, which (via HKDF) unwraps the vault key.
// userVerification is always "required": CTAP2 hmac-secret returns different
// outputs with and without UV, so it must be consistent.

function fromB64url(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function toB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function ensureSupport() {
  if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("UNSUPPORTED_BROWSER");
  }
}

function wrapError(e) {
  if (e && e.name) return new Error(`${e.name}: ${e.message}`);
  return e instanceof Error ? e : new Error(String(e));
}

async function assertPrf(opts) {
  const evalByCredential = {};
  for (const p of opts.passkeys) {
    evalByCredential[p.credential_id] = { first: fromB64url(p.prf_salt) };
  }
  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        rpId: opts.rp_id,
        challenge: fromB64url(opts.challenge),
        allowCredentials: opts.passkeys.map((p) => ({
          type: "public-key",
          id: fromB64url(p.credential_id),
        })),
        userVerification: "required",
        timeout: 300000,
        extensions: { prf: { evalByCredential } },
      },
    });
  } catch (e) {
    throw wrapError(e);
  }
  const ext = assertion.getClientExtensionResults();
  const first = ext.prf && ext.prf.results && ext.prf.results.first;
  if (!first) throw new Error("PRF_UNSUPPORTED");
  return { credential_id: toB64url(assertion.rawId), prf_output: toB64url(first) };
}

// opts: { rp_id, challenge, passkeys: [{ credential_id, prf_salt }] }
export async function evaluatePrf(json) {
  ensureSupport();
  return JSON.stringify(await assertPrf(JSON.parse(json)));
}

// opts: RegisterInfo from the protocol crate.
export async function registerPasskey(json) {
  ensureSupport();
  const opts = JSON.parse(json);
  const salt = fromB64url(opts.prf_salt);
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: opts.rp_id, name: "agentpass" },
        user: {
          id: fromB64url(opts.user_id),
          name: opts.user_name,
          displayName: opts.user_name,
        },
        challenge: fromB64url(opts.challenge),
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "discouraged",
          userVerification: "required",
        },
        excludeCredentials: opts.exclude_credentials.map((id) => ({
          type: "public-key",
          id: fromB64url(id),
        })),
        timeout: 300000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw wrapError(e);
  }
  const credentialId = toB64url(cred.rawId);
  const ext = cred.getClientExtensionResults();
  const first = ext.prf && ext.prf.results && ext.prf.results.first;
  if (first) {
    return JSON.stringify({ credential_id: credentialId, prf_output: toB64url(first) });
  }
  if (!ext.prf || ext.prf.enabled === false) throw new Error("PRF_UNSUPPORTED");
  // Many authenticators only evaluate PRF during authentication.
  const result = await assertPrf({
    rp_id: opts.rp_id,
    challenge: opts.challenge,
    passkeys: [{ credential_id: credentialId, prf_salt: opts.prf_salt }],
  });
  return JSON.stringify(result);
}
