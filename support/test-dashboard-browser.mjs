// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Host-only Chromium/Edge rendering checks against the existing GET-only
// synthetic preview. No package download, existing browser profile, real API,
// account, NAS, device or Docker access. Requires Node 24+ and --browser PATH.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, mkdir, writeFile, rm, realpath, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
assert.equal(process.argv.length, 4, "usage: node support/test-dashboard-browser.mjs --browser PATH");
assert.equal(process.argv[2], "--browser", "an explicit browser path is required");
const browserPath = await realpath(process.argv[3]);
assert.ok((await lstat(browserPath)).isFile(), "browser must be a regular file");
assert.ok(/^(msedge|chrome|chromium)(\.exe)?$/i.test(basename(browserPath)), "unsupported browser executable");
assert.ok(typeof WebSocket === "function", "Node with native WebSocket support is required");
assert.ok(Number(process.versions.node.split(".")[0]) >= 24, "Node 24+ is required");

const abort = new AbortController();
const deadline = setTimeout(() => abort.abort(new Error("browser test deadline exceeded")), 90_000);
const children = [];
const tempRoot = await realpath(tmpdir());
let profile, cdp;
let successful = false;
let failure, result;
const artifacts = join(repo, "artifacts", "dashboard-browser");
const uiHashes = async () => {
  const hashes = {};
  for (const name of ["index.html", "app.css", "app.js", "service-policy.js", "support-bundle.js", "ghost.svg"]) {
    const bytes = await readFile(join(repo, "src", "phantowd-api", "ui", name));
    assert.ok(bytes.length <= 65536, "dashboard source exceeded asset budget");
    hashes[name] = createHash("sha256").update(bytes).digest("hex");
  }
  return hashes;
};
const sourceHashes = await uiHashes();
await mkdir(artifacts, { recursive: true });
await writeFile(join(artifacts, "result.json"), JSON.stringify({
  schema_version: 1, status: "running", scope: "headless-browser-synthetic-preview-only", ui_sha256: sourceHashes,
}, null, 2) + "\n");

function start(file, args, options = {}) {
  const child = spawn(file, args, { cwd: repo, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], ...options });
  child.finished = new Promise((accept, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => accept({ code, signal }));
  });
  // Keep startup errors handled until a specific readiness wait observes them.
  child.finished.catch(() => {});
  children.push(child);
  return child;
}

function live(child) { return child.exitCode === null && child.signalCode === null; }

async function settled(child, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      child.finished.then(() => true),
      new Promise((accept) => { timer = setTimeout(() => accept(false), milliseconds); }),
    ]);
  } finally { clearTimeout(timer); }
}

async function until(probe, child, label, milliseconds = 10_000) {
  const expires = performance.now() + milliseconds;
  while (performance.now() < expires) {
    abort.signal.throwIfAborted();
    if (child && !live(child)) throw new Error(`${label}: process exited`);
    const result = await probe();
    if (result) return result;
    await delay(50, undefined, { signal: abort.signal });
  }
  throw new Error(`${label}: deadline exceeded`);
}

class CDP {
  constructor(socket) {
    this.socket = socket;
    this.sequence = 0;
    this.pending = new Map();
    this.exceptions = 0;
    this.requests = [];
    socket.addEventListener("message", ({ data }) => {
      try {
        assert.ok(typeof data === "string" && data.length <= 16 * 1024 * 1024, "protocol message exceeded");
        const message = JSON.parse(data);
        if (message.id) {
          const waiter = this.pending.get(message.id);
          if (!waiter) return;
          this.pending.delete(message.id);
          clearTimeout(waiter.timer);
          if (message.error) waiter.reject(new Error("browser protocol request refused"));
          else waiter.accept(message.result);
        } else if (message.method === "Runtime.exceptionThrown") {
          this.exceptions++;
        } else if (message.method === "Network.requestWillBeSent") {
          if (this.requests.length >= 256) throw new Error("browser request census exceeded");
          this.requests.push({ url: message.params.request.url, method: message.params.request.method });
        }
      } catch {
        this.fault = new Error("invalid or excessive browser protocol message");
        this.stop();
      }
    });
    const stop = () => {
      for (const waiter of this.pending.values()) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error("browser protocol closed"));
      }
      this.pending.clear();
    };
    this.stop = stop;
    socket.addEventListener("close", stop);
    abort.signal.addEventListener("abort", stop, { once: true });
  }
  send(method, params = {}, sessionId) {
    // Cleanup remains bounded and possible after the work deadline expires.
    if (method !== "Browser.close") {
      abort.signal.throwIfAborted();
      if (this.fault) throw this.fault;
    }
    assert.ok(this.pending.size < 16, "protocol concurrency exceeded");
    return new Promise((accept, reject) => {
      const id = ++this.sequence;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`browser protocol deadline: ${method}`));
      }, 5_000);
      this.pending.set(id, { accept, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
}

try {
  profile = await mkdtemp(join(tempRoot, "phantowd-dashboard-browser-"));
  const preview = start(process.execPath, [join(repo, "support", "dashboard-preview.mjs")], {
    env: { ...process.env, PHANTOWD_PREVIEW_PORT: "0" },
  });
  let previewText = "";
  let previewOutputExceeded = false;
  preview.stdout.on("data", (data) => {
    if (previewText.length + data.length > 4096) { previewOutputExceeded = true; return; }
    previewText += data;
  });
  preview.stderr.resume();
  const origin = await until(() => {
    assert.ok(!previewOutputExceeded, "preview output exceeded");
    const match = /^Dashboard preview at (http:\/\/127\.0\.0\.1:([0-9]+))\/ \(synthetic data only\)\r?\n$/.exec(previewText);
    if (!match) return null;
    assert.ok(Number(match[2]) >= 1024 && Number(match[2]) <= 65535, "unexpected preview port");
    return match[1];
  }, preview, "synthetic preview startup");

  const browser = start(browserPath, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    "--disable-background-networking", "--disable-component-update", "--disable-default-apps",
    "--disable-extensions", "--disable-sync", "--disable-domain-reliability",
    "--metrics-recording-only", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
    "--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1",
    `--user-data-dir=${profile}`, "about:blank",
  ]);
  browser.isBrowser = true;
  browser.stdout.resume();
  browser.stderr.resume();
  const endpoint = await until(async () => {
    let text;
    try { text = await readFile(join(profile, "DevToolsActivePort"), "utf8"); }
    catch (error) { if (error.code === "ENOENT") return null; throw error; }
    const match = /^([0-9]+)\r?\n(\/devtools\/browser\/[a-z0-9-]+)\r?\n?$/.exec(text);
    assert.ok(match, "unexpected owned browser endpoint");
    const port = Number(match[1]);
    assert.ok(port >= 1024 && port <= 65535, "unexpected debugging port");
    return `ws://127.0.0.1:${port}${match[2]}`;
  }, browser, "owned headless browser startup");
  const socket = new WebSocket(endpoint);
  await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error("browser connection deadline")), 5_000);
    socket.addEventListener("open", () => { clearTimeout(timer); accept(); }, { once: true });
    socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("browser connection refused")); }, { once: true });
  });
  cdp = new CDP(socket);
  const version = await cdp.send("Browser.getVersion");
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const send = (method, params) => cdp.send(method, params, sessionId);
  const evaluate = async (expression) => {
    const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    assert.ok(!result.exceptionDetails, "browser evaluation failed");
    return result.result.value;
  };
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Page.navigate", { url: origin });
  await until(() => evaluate(`document.getElementById('snapshot-status')?.textContent === 'Read-only system, storage, RAID, and mount observations updated.'`), browser, "rendered synthetic snapshot");
  assert.equal(await evaluate("document.getElementById('profile-notice-mark').textContent"), "FIXTURE DATA");
  assert.equal(await evaluate("document.getElementById('dashboard-content').hidden"), false);
  assert.equal(await evaluate("document.getElementById('auth-panel').hidden"), true);
  assert.equal(await evaluate("document.getElementById('support-download').disabled"), false);
  assert.equal(await evaluate("getComputedStyle(document.body).backgroundColor"), "rgb(16, 19, 27)", "dashboard stylesheet was not applied");

  // Use actual browser keyboard dispatch, not HTMLElement.focus(), for Tab.
  await send("Page.navigate", { url: origin });
  await until(() => evaluate(`document.getElementById('snapshot-status')?.textContent === 'Read-only system, storage, RAID, and mount observations updated.'`), browser, "keyboard page load");
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 });
  assert.equal(await evaluate("document.activeElement.id"), "skip-to-content");
  assert.equal(await evaluate("getComputedStyle(document.activeElement).outlineStyle !== 'none'"), true);
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  assert.equal(await evaluate("document.activeElement.id"), "main-content");

  await evaluate("document.activeElement.blur(); window.scrollTo(0, 0)");
  const layouts = [];
  for (const width of [1365, 390, 320]) {
    await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
    const layout = await evaluate(`(() => ({width: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth, client: document.documentElement.clientWidth}))()`);
    layouts.push(layout);
    const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
    assert.ok(shot.data.length <= 8 * 1024 * 1024, "screenshot exceeded output budget");
    await writeFile(join(artifacts, `overview-${width}.png`), Buffer.from(shot.data, "base64"));
    assert.equal(layout.width, width, "viewport override did not apply");
    assert.ok(layout.document <= layout.client && layout.body <= layout.client, `horizontal overflow at ${width}px: ${JSON.stringify(layout)}`);
  }
  const before = cdp.requests.filter((r) => new URL(r.url).pathname === "/api/v1/system").length;
  await evaluate("document.getElementById('refresh').click()");
  await until(() => evaluate(`document.getElementById('snapshot-status')?.textContent === 'Read-only system, storage, RAID, and mount observations updated.' && !document.getElementById('refresh').disabled`), browser, "explicit browser refresh");
  assert.equal(cdp.requests.filter((r) => new URL(r.url).pathname === "/api/v1/system").length, before + 1);
  assert.equal(cdp.exceptions, 0, "uncaught page JavaScript exception");
  assert.ok(!cdp.fault, "browser protocol observation failed");
  for (const request of cdp.requests) {
    assert.equal(new URL(request.url).origin, origin, "page attempted an external request");
    assert.equal(request.method, "GET", "read-only preview attempted a mutation");
  }
  assert.ok(live(preview), "owned preview exited during browser verification");
  assert.deepEqual(await uiHashes(), sourceHashes, "dashboard source changed during browser verification");
  result = {
    schema_version: 1, scope: "headless-browser-synthetic-preview-only", browser: version.product,
    ui_sha256: sourceHashes,
    layouts, keyboard_skip_link: true, explicit_refresh: true, page_requests: cdp.requests.length,
    uncaught_exceptions: cdp.exceptions, authentication_qualified: false, hardware_qualified: false,
  };
  successful = true;
} catch (error) {
  failure = error;
} finally {
  clearTimeout(deadline);
  try {
    if (cdp) {
      // Browser.close may close the socket before acknowledging the command.
      await cdp.send("Browser.close").catch(() => {});
    }
    for (const child of children.toReversed()) {
      if (live(child)) {
        // The preview intentionally runs until signaled; it needs no idle wait.
        if (!child.isBrowser) child.kill();
        else if (!await settled(child, 3000) && live(child)) child.kill();
      }
      assert.ok(await settled(child, 5000), "owned process did not stop");
    }
    if (profile) {
      // Validate this exact owned target before any Windows recursive removal.
      assert.equal(dirname(resolve(profile)), tempRoot, "profile escaped temporary root");
      assert.ok(basename(profile).startsWith("phantowd-dashboard-browser-"));
      assert.ok(!(await lstat(profile)).isSymbolicLink(), "profile became a link");
      await rm(profile, { recursive: true });
    }
  } catch (error) {
    failure = new AggregateError([failure, error].filter(Boolean), "browser verification or cleanup failed");
  }
}
if (failure) {
  await writeFile(join(artifacts, "result.json"), JSON.stringify({
    schema_version: 1, status: "failed", scope: "headless-browser-synthetic-preview-only", ui_sha256: sourceHashes,
  }, null, 2) + "\n");
  throw failure;
}
assert.ok(successful, "browser test did not finish");
await writeFile(join(artifacts, "result.json"), JSON.stringify({ ...result, status: "passed", owned_profile_removed: true }, null, 2) + "\n");
console.log("PHANTOWD_DASHBOARD_BROWSER_READY scope=synthetic-preview-only viewports=3 keyboard=skip-link requests=read-only");
