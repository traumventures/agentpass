import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { sandbox, virtualAuthenticator } from "./helpers.js";

const EXIT_LOCKED = 3;
const EXIT_NOT_FOUND = 4;
const EXIT_TIMEOUT = 5;

async function setupVault(page, ap, label = "Virtual key") {
  const setup = ap.start(["setup", "--name", "e2e"]);
  await page.goto(await setup.url);
  await expect(page.getByRole("heading", { name: "Create your vault" })).toBeVisible();
  // The token is removed from the address bar right away.
  expect(page.url()).not.toContain("#");
  await page.getByLabel("Passkey label").fill(label);
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: "All set" })).toBeVisible();
  const res = await setup.done;
  expect(res.code, res.stderr).toBe(0);
}

async function unlockVia(page, ap, args, choose) {
  const unlock = await ap.run(["unlock", ...args]);
  expect(unlock.code, unlock.stderr).toBe(0);
  const url = unlock.stdout.trim();
  expect(url).toMatch(/^http:\/\/localhost:\d+\/unlock#/);
  await page.goto(url);
  await expect(page.getByRole("heading", { name: "Unlock vault" })).toBeVisible();
  if (choose) await choose(page);
  await page.getByRole("button", { name: "Unlock with passkey" }).click();
  await expect(page.getByRole("heading", { name: "All set" })).toBeVisible();
}

test("setup, set, unlock with a chosen duration, get, run, lock", async ({ page }) => {
  const ap = await sandbox();
  try {
    await virtualAuthenticator(page);
    await setupVault(page, ap);

    const toml = readFileSync(ap.vault, "utf8");
    expect(toml).toContain('label = "Virtual key"');
    expect(toml).toContain('name = "e2e"');

    let r = await ap.run(["set", "GITHUB_TOKEN", "-d", "CI token"], { input: "ghp_e2e_secret\n" });
    expect(r.code, r.stderr).toBe(0);
    r = await ap.run(["set", "BINARY"], { input: Buffer.from([0, 1, 2, 255]) });
    expect(r.code, r.stderr).toBe(0);
    const stored = readFileSync(ap.vault, "utf8");
    expect(stored).toContain('description = "CI token"');
    expect(stored).not.toContain("ghp_e2e_secret");

    r = await ap.run(["list"]);
    expect(r.stdout).toMatch(/GITHUB_TOKEN\s+CI token/);

    // Locked: get fails with exit code 3, wait times out with 5.
    r = await ap.run(["get", "GITHUB_TOKEN"]);
    expect(r.code).toBe(EXIT_LOCKED);
    r = await ap.run(["wait", "--timeout", "1s"]);
    expect(r.code).toBe(EXIT_TIMEOUT);
    r = await ap.run(["status"]);
    expect(r.code).toBe(EXIT_LOCKED);
    expect(r.stdout).toContain("locked");

    // The agent requests an unlock and blocks; the user picks 15 minutes.
    const waiter = ap.start(["wait", "--timeout", "60s"]);
    await unlockVia(page, ap, ["--suggest", "2h"], async (p) => {
      await expect(p.getByText("Your agent suggested: 2 hours")).toBeVisible();
      await expect(p.getByLabel("Custom duration")).toHaveValue("2");
      await p.getByText("15 min").click();
    });
    r = await waiter.done;
    expect(r.code, r.stderr).toBe(0);

    r = await ap.run(["status", "--json"]);
    expect(r.code).toBe(0);
    const status = JSON.parse(r.stdout);
    expect(status.unlocked).toBe(true);
    expect(status.expires_in_secs).toBeGreaterThan(14 * 60);
    expect(status.expires_in_secs).toBeLessThanOrEqual(15 * 60);

    r = await ap.run(["get", "GITHUB_TOKEN"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe("ghp_e2e_secret");
    r = await ap.run(["get", "NOPE"]);
    expect(r.code).toBe(EXIT_NOT_FOUND);

    r = await ap.run(["run", "-e", "GH=GITHUB_TOKEN", "--", "sh", "-c", 'printf "%s" "$GH"']);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe("ghp_e2e_secret");
    r = await ap.run(["run", "-e", "GITHUB_TOKEN", "--", "sh", "-c", "exit 7"]);
    expect(r.code).toBe(7);

    // Already unlocked: no new link.
    r = await ap.run(["unlock"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");

    r = await ap.run(["lock"]);
    expect(r.code).toBe(0);
    r = await ap.run(["get", "GITHUB_TOKEN"]);
    expect(r.code).toBe(EXIT_LOCKED);
  } finally {
    await ap.cleanup();
  }
});

test("until locked, backup passkey enrollment and removal", async ({ page }) => {
  const ap = await sandbox();
  try {
    const first = await virtualAuthenticator(page);
    await setupVault(page, ap, "Primary");
    await ap.run(["set", "API_KEY"], { input: "k-123" });

    await unlockVia(page, ap, ["--suggest", "forever"], async (p) => {
      await expect(p.getByText("Your agent suggested: until locked")).toBeVisible();
    });
    let r = await ap.run(["status", "--json"]);
    expect(JSON.parse(r.stdout).expires_in_secs).toBeNull();

    // Enroll a backup on a second authenticator.
    await first.remove();
    const backup = await virtualAuthenticator(page);
    const add = ap.start(["passkey", "add", "--label", "Backup"]);
    await page.goto(await add.url);
    await expect(page.getByRole("heading", { name: "Add a passkey" })).toBeVisible();
    await page.getByRole("button", { name: "Add passkey" }).click();
    await expect(page.getByRole("heading", { name: "All set" })).toBeVisible();
    r = await add.done;
    expect(r.code, r.stderr).toBe(0);
    r = await ap.run(["passkey", "list"]);
    expect(r.stdout).toContain("Primary");
    expect(r.stdout).toContain("Backup");

    // Only the backup authenticator is present now; it unlocks the vault.
    await ap.run(["lock"]);
    await unlockVia(page, ap, []);
    r = await ap.run(["get", "API_KEY"]);
    expect(r.stdout).toBe("k-123");
    expect((await backup.credentials()).length).toBe(1);

    r = await ap.run(["passkey", "remove", "Primary"]);
    expect(r.code, r.stderr).toBe(0);
    r = await ap.run(["passkey", "remove", "Backup"]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain("only passkey");

    r = await ap.run(["lock", "--all"]);
    expect(r.code).toBe(0);
    r = await ap.run(["status", "--all"]);
    expect(r.code).toBe(EXIT_LOCKED);
  } finally {
    await ap.cleanup();
  }
});

test("passkeys without PRF are refused", async ({ page }) => {
  const ap = await sandbox();
  try {
    await virtualAuthenticator(page, { prf: false });
    const setup = ap.start(["setup", "--timeout", "20s"]);
    await page.goto(await setup.url);
    await page.getByRole("button", { name: "Create passkey" }).click();
    await expect(page.getByRole("alert")).toContainText("does not support the PRF extension");
    setup.child.kill("SIGINT");
  } finally {
    await ap.cleanup();
  }
});

test("web server rejects foreign origins, hosts and missing tokens", async ({ page, request }) => {
  const ap = await sandbox();
  try {
    await virtualAuthenticator(page);
    await setupVault(page, ap);
    const unlock = await ap.run(["unlock"]);
    const url = new URL(unlock.stdout.trim());
    const token = url.hash.slice(1);
    const base = `http://localhost:${ap.port}`;
    const body = { kind: "unlocked", credential_id: "AA", prf_output: "AA", duration_secs: 60 };

    let r = await request.post(`${base}/api/flow/complete`, {
      headers: { "x-agentpass-token": token, origin: "http://evil.example" },
      data: body,
    });
    expect(r.status()).toBe(403);
    r = await request.get(`http://127.0.0.1:${ap.port}/api/flow`, {
      headers: { "x-agentpass-token": token, host: `evil.example:${ap.port}` },
    });
    expect(r.status()).toBe(421);
    r = await request.get(`${base}/api/flow`);
    expect(r.status()).toBe(400);
    r = await request.get(`${base}/api/flow`, { headers: { "x-agentpass-token": "bogus" } });
    expect(r.status()).toBe(404);

    const page200 = await request.get(`${base}/unlock`);
    expect(page200.status()).toBe(200);
    const csp = page200.headers()["content-security-policy"];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toMatch(/script-src 'self' 'wasm-unsafe-eval' 'sha256-/);
    expect(page200.headers()["x-frame-options"]).toBe("DENY");

    // A link without its token explains itself.
    await page.goto(`${base}/unlock`);
    await expect(page.getByText("needs the full link")).toBeVisible();
  } finally {
    await ap.cleanup();
  }
});
