import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const BIN =
  process.env.AGENTPASS_BIN ?? resolve(import.meta.dirname, "../../target/debug/agentpass");

async function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => ok(port));
    });
    srv.on("error", fail);
  });
}

/** An isolated agentpass environment: own runtime dir, port and vault. */
export async function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "agentpass-e2e-"));
  const port = await freePort();
  const env = {
    ...process.env,
    AGENTPASS_RUNTIME_DIR: join(dir, "run"),
    AGENTPASS_PORT: String(port),
    AGENTPASS_VAULT: join(dir, "secrets.agentpass.toml"),
    NO_COLOR: "1",
  };
  delete env.XDG_SESSION_ID;

  /** Starts the CLI; resolves with {code, stdout, stderr} when it exits. */
  function start(args, { input } = {}) {
    const child = spawn(BIN, args, { env, cwd: dir, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
    const done = new Promise((ok) =>
      child.on("close", (code) => ok({ code, stdout, stderr })),
    );
    /** Resolves with the first http URL printed on stdout. */
    const url = new Promise((ok, fail) => {
      const check = () => {
        const m = stdout.match(/http:\/\/localhost:\d+\/\S+/);
        if (m) ok(m[0]);
      };
      child.stdout.on("data", check);
      child.on("close", () => {
        check();
        fail(new Error(`no URL printed; stderr: ${stderr}`));
      });
    });
    url.catch(() => {});
    return { child, done, url };
  }

  const run = (args, opts) => start(args, opts).done;

  async function cleanup() {
    await run(["daemon", "--stop"]);
    rmSync(dir, { recursive: true, force: true });
  }

  return { dir, port, env, start, run, cleanup, vault: env.AGENTPASS_VAULT };
}

/** Adds a CTAP2 virtual authenticator (with or without PRF) to the page. */
export async function virtualAuthenticator(page, { prf = true } = {}) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: prf,
      automaticPresenceSimulation: true,
    },
  });
  return {
    cdp,
    id: authenticatorId,
    remove: () => cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }),
    credentials: async () =>
      (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials,
  };
}
