// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fast host-only boundary tests. This starts only the synthetic Node preview,
// never a browser, Go API, emulator, container or device operation.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
function preview(port) {
  const child = spawn(process.execPath, [resolve(repo, "support/dashboard-preview.mjs")], {
    cwd: repo, env: { ...process.env, PHANTOWD_PREVIEW_PORT: port }, windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return child;
}
async function exited(child, milliseconds) {
  let timer;
  try {
    if (child.exitCode !== null || child.signalCode !== null) return [child.exitCode, child.signalCode];
    return await Promise.race([
      once(child, "exit"),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("preview process deadline exceeded")), milliseconds); }),
    ]);
  } finally { clearTimeout(timer); }
}
const invalid = ["", " ", "000", "01", "80", "1023", "65536", "-1", "+1024", "1e4", "0x400", "Infinity"];
for (const port of invalid) {
  const child = preview(port);
  let output = "";
  child.stdout.on("data", (data) => { if (output.length < 4096) output += data; });
  child.stderr.resume();
  try {
    const [code] = await exited(child, 3000);
    assert.notEqual(code, 0, "invalid port was accepted");
    assert.equal(output, "", "invalid port started a preview");
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited(child, 3000);
  }
}
const child = preview("0");
let output = "";
child.stdout.on("data", (data) => { if (output.length < 4096) output += data; });
child.stderr.resume();
try {
  const origin = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error("ephemeral preview startup deadline exceeded")), 3000);
    child.stdout.on("data", () => {
      const match = /^Dashboard preview at (http:\/\/127\.0\.0\.1:([0-9]+))\/ \(synthetic data only\)\r?\n$/.exec(output);
      if (!match) return;
      clearTimeout(timer);
      const port = Number(match[2]);
      if (port < 1024 || port > 65535) reject(new Error("preview bound unexpected port"));
      else accept(match[1]);
    });
    child.once("exit", () => { clearTimeout(timer); reject(new Error("preview exited before startup")); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
  for (const [path, method, status] of [
    ["/", "GET", 200], ["/assets/app.css", "GET", 200], ["/assets/app.js", "GET", 200],
    ["/assets/service-policy.js", "GET", 200], ["/assets/support-bundle.js", "GET", 200],
    ["/assets/ghost.svg", "GET", 200], ["/api/v1/system", "GET", 200],
    ["/assets/auth.js", "GET", 200],
    ["/api/v1/storage", "GET", 200], ["/api/v1/arrays", "GET", 200], ["/api/v1/mounts", "GET", 200],
    ["/api/v1/auth/status", "GET", 200], ["/?unexpected=1", "GET", 400],
    ["/", "POST", 405], ["/not-a-route", "GET", 404],
  ]) {
    const response = await fetch(origin + path, { method, redirect: "error", signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, status, `${method} ${path}`);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    const body = await response.text();
    assert.ok(Buffer.byteLength(body) <= 65536, "fixture response exceeded asset budget");
    if (path === "/api/v1/system") {
      const system = JSON.parse(body);
      assert.equal(system.target, "ui-preview-fixture");
      assert.equal(system.flashable, false);
      assert.equal(system.hardware_validated, false);
    }
  }
} finally {
  if (child.exitCode === null && child.signalCode === null) child.kill();
  await exited(child, 3000);
}
console.log("Dashboard preview boundaries passed: invalid-ports=12 ephemeral-loopback=true routes=15 mutations=false devices=false.");
