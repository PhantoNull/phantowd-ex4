// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Host-only Chromium/Edge rendering checks against the existing GET-only
// synthetic preview. No package download, existing browser profile, real API,
// account, NAS, device or Docker access. Optional --api-fixture PATH uses a
// separately compiled Go test binary with actual auth and memory-only accounts.
// Requires Node 24+ and --browser PATH.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, mkdir, writeFile, rm, realpath, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { classifyPageResource } from "./browser-resource-contract.mjs";
import { iscsiExposurePolicyFixture, iscsiDraftFieldsFixture } from "./tests/test-iscsi-panel.mjs";
import { networkPolicyFixture, networkDraftFieldsFixture } from "./tests/test-network-panel.mjs";
import { readOwnedBrowserEndpoint } from "./browser-startup-contract.mjs";
import { exerciseServicePolicy } from "./browser-service-policy-flow.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
assert.ok([4, 6, 7].includes(process.argv.length), "usage: node support/test-dashboard-browser.mjs --browser PATH [--api-fixture PATH [--network-preview|--service-policy]]");
assert.equal(process.argv[2], "--browser", "an explicit browser path is required");
let apiFixture;
if (process.argv.length >= 6) {
  assert.equal(process.argv[4], "--api-fixture");
  apiFixture = await realpath(process.argv[5]);
  assert.ok((await lstat(apiFixture)).isFile(), "API fixture must be a regular test binary");
  assert.ok(/^phantowd-browser-api\.test(\.exe)?$/.test(basename(apiFixture)), "unexpected API fixture binary name");
}
if (process.argv.length === 7) assert.ok(["--network-preview", "--service-policy"].includes(process.argv[6]));
const networkMode = process.argv[6] === "--network-preview";
const serviceMode = process.argv[6] === "--service-policy";
const scope = serviceMode ? "headless-browser-service-policy-memory-fixture" : networkMode ? "headless-browser-network-preview-go-auth-memory-fixture" : apiFixture ? "headless-browser-go-auth-memory-fixture" : "headless-browser-synthetic-preview-only";
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
const artifacts = join(repo, "artifacts", serviceMode ? "dashboard-browser-policy" : networkMode ? "dashboard-browser-network" : apiFixture ? "dashboard-browser-api" : "dashboard-browser");
const uiHashes = async () => {
  const hashes = {};
  for (const name of ["index.html", "app.css", "app.js", "auth.js", "service-policy.js", "support-bundle.js", "iscsi-preview.js", "network-preview.js", "ghost.svg"]) {
    const bytes = await readFile(join(repo, "src", "phantowd-api", "ui", name));
    assert.ok(bytes.length <= 65536, "dashboard source exceeded asset budget");
    hashes[name] = createHash("sha256").update(bytes).digest("hex");
  }
  return hashes;
};
const sourceHashes = await uiHashes();
const harnessHashes = async () => {
  const hashes = {};
  for (const name of ["support/test-dashboard-browser.mjs", "support/browser-resource-contract.mjs", "support/browser-startup-contract.mjs", "support/browser-service-policy-flow.mjs", "support/tests/test-iscsi-panel.mjs", "support/tests/test-network-panel.mjs"]) {
    const bytes = await readFile(join(repo, name));
    assert.ok(bytes.length <= 65536, "browser harness source exceeded budget");
    hashes[name] = createHash("sha256").update(bytes).digest("hex");
  }
  return hashes;
};
const harnessSourceHashes = await harnessHashes();
await mkdir(artifacts, { recursive: true });
await writeFile(join(artifacts, "result.json"), JSON.stringify({
  schema_version: 1, status: "running", scope, ui_sha256: sourceHashes, harness_sha256: harnessSourceHashes,
}, null, 2) + "\n");

function start(file, args, options = {}) {
  const child = spawn(file, args, { cwd: repo, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], ...options });
  child.finished = new Promise((accept, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => accept({ code, signal }));
  });
  // Keep startup errors handled until a specific readiness wait observes them.
  child.finished.catch(() => {});
  children.push(child);
  return child;
}

function live(child) { return Boolean(child.pid) && child.exitCode === null && child.signalCode === null; }

async function settled(child, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      child.finished.then(() => true, () => true),
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
    this.paused = [];
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
        } else if (message.method === "Fetch.requestPaused") {
          assert.ok(this.paused.length < 7, "interception count exceeded");
          // Retain only the protocol request handle, never credentials/headers.
          this.paused.push(message.params.requestId);
        } else if (message.method === "Network.requestWillBeSent") {
          if (this.requests.length >= 256) throw new Error("browser request census exceeded");
          assert.ok(typeof message.params.request.url === "string" && message.params.request.url.length <= 8192, "browser request URL exceeded");
          this.requests.push({ url: message.params.request.url, method: message.params.request.method, resourceType: message.params.type });
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
  const preview = apiFixture ? start(apiFixture, ["-test.run=^TestDashboardBrowserAPIFixture$", "-test.timeout=90s"], {
    env: { ...process.env, PHANTOWD_BROWSER_API_FIXTURE: "1", PHANTOWD_BROWSER_POLICY_FIXTURE: serviceMode ? "1" : "0" }, stdio: ["pipe", "pipe", "pipe"],
  }) : start(process.execPath, [join(repo, "support", "dashboard-preview.mjs")], {
    env: { ...process.env, PHANTOWD_PREVIEW_PORT: "0" },
  });
  preview.isAPIFixture = Boolean(apiFixture);
  preview.stdin?.on("error", () => { preview.stopWriteFailed = true; });
  let previewText = "";
  let previewOutputExceeded = false;
  let previewErrorOutput = false;
  preview.stdout.on("data", (data) => {
    if (previewText.length + data.length > 4096) { previewOutputExceeded = true; return; }
    previewText += data;
  });
  preview.stderr.on("data", () => { previewErrorOutput = true; });
  preview.stopVerified = () => !preview.stopWriteFailed && !previewOutputExceeded && !previewErrorOutput &&
    previewText.includes("PHANTOWD_BROWSER_API_STOPPED account=memory-only");
  const origin = await until(() => {
    assert.ok(!previewOutputExceeded, "preview output exceeded");
    const match = (apiFixture ? /^Dashboard API fixture at (http:\/\/127\.0\.0\.1:([0-9]+))\/ \(test-only authentication\)\r?\n/m :
      /^Dashboard preview at (http:\/\/127\.0\.0\.1:([0-9]+))\/ \(synthetic data only\)\r?\n$/).exec(previewText);
    if (!match) return null;
    if (apiFixture) {
      const manifest = /^PHANTOWD_BROWSER_API_ASSETS (\{[^\r\n]+\})\r?$/m.exec(previewText);
      if (!manifest) return null;
      assert.deepEqual(JSON.parse(manifest[1]), sourceHashes, "Go fixture embeds stale UI assets");
    }
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
  const endpoint = await until(() => readOwnedBrowserEndpoint(join(profile, "DevToolsActivePort")), browser, "owned headless browser startup");
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
  const pointerControls = [];
  const key = async (key, code, windowsVirtualKeyCode, modifiers = 0) => {
    for (const type of ["keyDown", "keyUp"]) {
      await send("Input.dispatchKeyEvent", { type, key, code, windowsVirtualKeyCode, modifiers,
        ...(type === "keyDown" && key === "Enter" ? { text: "\r", unmodifiedText: "\r" } : {}),
      });
    }
  };
  const clickVisible = async (id) => {
    assert.ok(pointerControls.length < 32, "visible pointer action budget exceeded");
    const point = await evaluate(`(() => {
      const e = document.getElementById(${JSON.stringify(id)});
      if (!e || e.disabled || e.closest('[hidden]')) return null;
      e.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
      const r = e.getBoundingClientRect(), s = getComputedStyle(e);
      if (!e.getClientRects().length || r.width <= 0 || r.height <= 0 || s.visibility !== 'visible') return null;
      const x = r.x + r.width / 2, y = r.y + r.height / 2;
      if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return null;
      const hit = document.elementFromPoint(x, y);
      return hit && (hit === e || e.contains(hit)) ? { x, y } : null;
    })()`);
    assert.ok(point, `control is not visible/hit-testable: ${id}`);
    await send("Input.dispatchMouseEvent", { type: "mousePressed", ...point, button: "left", clickCount: 1 });
    await send("Input.dispatchMouseEvent", { type: "mouseReleased", ...point, button: "left", clickCount: 1 });
    pointerControls.push(id);
  };
  const replaceInput = async (id, text) => {
    assert.equal(await evaluate("document.activeElement.id"), id, "input must have actual browser focus");
    await key("a", "KeyA", 65, 2);
    await send("Input.insertText", { text });
  };
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Page.navigate", { url: origin });
  const snapshotReady = apiFixture ? `!document.getElementById('dashboard-content').hidden && !document.getElementById('refresh').disabled && document.getElementById('kernel-value').textContent === 'Linux 6.18.53' && document.getElementById('snapshot-status').textContent === 'system observation is current. storage, RAID, mount observations unavailable. Failed values were cleared.'` :
    `document.getElementById('snapshot-status')?.textContent === 'Read-only system, storage, RAID, and mount observations updated.' && !document.getElementById('refresh').disabled`;
  const signInReady = `!document.getElementById('auth-panel').hidden && !document.getElementById('auth-form').hidden && !document.getElementById('auth-submit').disabled && document.getElementById('auth-form').dataset.mode === 'login'`;
  const submitLogin = async (password) => {
    await clickVisible("auth-username");
    await replaceInput("auth-username", "browser-admin");
    await key("Tab", "Tab", 9);
    await replaceInput("auth-password", password);
    await key("Enter", "Enter", 13);
  };
  const changePassword = async (original, replacement) => {
    if (!await evaluate("document.getElementById('password-panel').open")) await clickVisible("password-title");
    await clickVisible("password-current");
    await replaceInput("password-current", original);
    await key("Tab", "Tab", 9);
    await replaceInput("password-new", replacement);
    await key("Tab", "Tab", 9);
    await replaceInput("password-confirm", replacement);
    await key("Tab", "Tab", 9);
    assert.equal(await evaluate("document.activeElement.id"), "password-submit");
    await key("Enter", "Enter", 13);
  };
  const fixturePassword = "browser fixture original passphrase";
  const nextPassword = "browser fixture replacement passphrase";
  const currentCookie = async () => {
    const { cookies } = await send("Network.getCookies", { urls: [origin] });
    assert.equal(cookies.length, 1, "unexpected fixture cookie roster");
    assert.equal(cookies[0].httpOnly, true, "session cookie was not HttpOnly");
    return `${cookies[0].name}=${cookies[0].value}`;
  };
  const cookieStatus = async (cookie) => {
    // Replay the exact former HttpOnly test cookie outside the browser jar.
    // Never log/store its value, response body or request headers.
    const response = await fetch(origin + "/api/v1/system", {
      headers: { Cookie: cookie }, redirect: "error", signal: AbortSignal.timeout(2000),
    });
    const status = response.status;
    await response.body?.cancel();
    return status;
  };
  if (apiFixture) {
    await until(() => evaluate(`!document.getElementById('auth-panel').hidden && document.getElementById('auth-form').dataset.mode === 'setup'`), browser, "actual setup form");
    assert.equal(await evaluate("document.getElementById('dashboard-content').hidden"), true);
    assert.equal(await evaluate("fetch('/api/v1/system').then(r => r.status)"), 401);
    await submitLogin(fixturePassword);
  }
  await until(() => evaluate(snapshotReady), browser, "rendered synthetic snapshot");
  assert.equal(await evaluate("document.getElementById('profile-notice-mark').textContent"), apiFixture ? "MEMORY-ONLY AUTH FIXTURE" : "FIXTURE DATA");
  if (apiFixture) {
    for (const id of ["logout", "logout-all", "password-panel"]) {
      assert.equal(await evaluate(`document.getElementById(${JSON.stringify(id)}).hidden`), false, "authentication control hidden by fixture profile");
    }
  }
  assert.equal(await evaluate("document.getElementById('dashboard-content').hidden"), false);
  assert.equal(await evaluate("document.getElementById('auth-panel').hidden"), true);
  assert.equal(await evaluate("document.getElementById('support-download').disabled"), false);
  assert.equal(await evaluate("getComputedStyle(document.body).backgroundColor"), "rgb(16, 19, 27)", "dashboard stylesheet was not applied");

  let servicePolicyResult;
  if (serviceMode) {
    const policyLayouts = [];
    const policyScreenshot = async (phase) => {
      const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      assert.ok(shot.data.length <= 8 * 1024 * 1024, "policy screenshot exceeded output budget");
      await writeFile(join(artifacts, `policy-${phase}-320.png`), Buffer.from(shot.data, "base64"));
    };
    const inspectLayout = async (phase) => {
      assert.ok(["draft", "review-1", "review-2", "review-3"].includes(phase), "unknown policy layout phase");
      const actionWidth = await evaluate("innerWidth");
      for (const width of [1365, 390, 320]) {
        await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
        const layout = await evaluate(`(() => {
          const root = document.getElementById('policy-form').closest('section');
          const controls = Array.from(root.querySelectorAll('input, select, button')).filter(e => e.getClientRects().length && getComputedStyle(e).visibility === 'visible');
          const client = document.documentElement.clientWidth;
          return { width: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth, client,
            visible_controls: controls.length,
            escaped_controls: controls.filter(e => { const r = e.getBoundingClientRect(); return r.left < -0.5 || r.right > client + 0.5; }).map(e => e.id).slice(0, 16),
            unlabeled_inputs: controls.filter(e => e.tagName !== 'BUTTON' && !e.labels?.length && !e.getAttribute('aria-label') && !e.getAttribute('aria-labelledby')).map(e => e.id).slice(0, 16) };
        })()`);
        layout.phase = phase;
        policyLayouts.push(layout);
        assert.ok(policyLayouts.length <= 12, "policy layout observation bound exceeded");
        await writeFile(join(artifacts, "policy-layouts.json"), JSON.stringify(policyLayouts, null, 2) + "\n");
        if (width === 320 && phase === "draft") {
          await evaluate("document.getElementById('policy-form').scrollIntoView({ block: 'start', behavior: 'instant' })");
          await policyScreenshot(phase);
        }
        assert.equal(layout.width, width, "policy viewport override did not apply");
        assert.ok(layout.visible_controls > 0 && layout.visible_controls <= 64, "policy controls unavailable or excessive");
        assert.ok(layout.document <= layout.client && layout.body <= layout.client, `policy horizontal overflow: ${JSON.stringify({ phase, ...layout })}`);
        assert.deepEqual(layout.escaped_controls, [], "policy input escaped the visible page");
        assert.deepEqual(layout.unlabeled_inputs, [], "policy input has no associated label");
        if (phase === "review-2" && width === 320) {
          layout.keyboard_regions = [];
          for (const id of ["service-diff", "service-overlaps"]) {
            let tabs = 0;
            while (!await evaluate(`document.activeElement === document.getElementById(${JSON.stringify(id)}).closest('.policy-diff-scroll')`) && tabs < 64) {
              await key("Tab", "Tab", 9); tabs++;
            }
            assert.equal(await evaluate(`document.activeElement === document.getElementById(${JSON.stringify(id)}).closest('.policy-diff-scroll')`), true, "policy review region is not keyboard reachable");
            const before = await evaluate(`(() => { const e = document.activeElement; return { left: e.scrollLeft, top: e.scrollTop, width: e.clientWidth, content: e.scrollWidth, height: e.clientHeight, full_height: e.scrollHeight, viewport_height: innerHeight, page_top: document.documentElement.scrollTop, outline: getComputedStyle(e).outlineStyle }; })()`);
            assert.ok(before.content > before.width, "narrow review must exercise a genuinely scrollable table");
            assert.ok(before.height <= before.viewport_height * 2 / 3, `review region consumes the viewport: ${JSON.stringify(before)}`);
            const vertical = before.full_height > before.height;
            if (id === "service-overlaps") assert.ok(vertical, "long folder-pair review must exercise vertically retained content");
            assert.notEqual(before.outline, "none", "keyboard review focus is not visible");
            await key("ArrowRight", "ArrowRight", 39);
            await until(() => evaluate(`document.activeElement.scrollLeft > ${before.left}`), browser, "keyboard policy table scrolling");
            assert.equal(await evaluate("document.documentElement.scrollLeft"), 0, "table keyboard scroll moved the whole page");
            if (vertical) {
              await key("ArrowDown", "ArrowDown", 40);
              await until(() => evaluate(`document.activeElement.scrollTop > ${before.top}`), browser, "keyboard policy table vertical scrolling");
              assert.equal(await evaluate("document.documentElement.scrollTop"), before.page_top, "table vertical scroll moved the whole page");
            }
            layout.keyboard_regions.push({ id, tabs, focus_visible: true, scroll_verified: true, vertical_scroll_verified: vertical,
              visible_height: before.height, full_height: before.full_height });
          }
          await key("Tab", "Tab", 9);
          const exit = await evaluate("({ tag: document.activeElement.tagName, inside: Boolean(document.activeElement.closest('.policy-diff-scroll')) })");
          assert.ok(!exit.inside && exit.tag !== "BODY", "policy review trapped keyboard focus");
          layout.keyboard_exit_verified = true;
          await writeFile(join(artifacts, "policy-layouts.json"), JSON.stringify(policyLayouts, null, 2) + "\n");
          await policyScreenshot(phase);
        }
      }
      await send("Emulation.setDeviceMetricsOverride", { width: actionWidth, height: 900, deviceScaleFactor: 1, mobile: false });
    };
    await send("Emulation.setDeviceMetricsOverride", { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
    servicePolicyResult = { ...await exerciseServicePolicy({ evaluate, clickVisible, replaceInput, key, until, browser, inspectLayout }), form_action_width: 320, layouts: policyLayouts };
    await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/file-services/configuration" && r.method === "PUT").length, 4);
  }
  if (apiFixture && !networkMode && !serviceMode) {
    await clickVisible("iscsi-document");
    await replaceInput("iscsi-document", JSON.stringify(iscsiExposurePolicyFixture()));
    await clickVisible("iscsi-submit");
    await until(() => evaluate(`!document.getElementById('iscsi-result').hidden && !document.getElementById('iscsi-submit').disabled`), browser, "actual iSCSI preview HTTP result");
    const displayed = await evaluate("document.getElementById('iscsi-result').textContent");
    assert.match(displayed, /LUN 0.*4096 bytes/);
    assert.match(displayed, /iqn\.2001-04\.com\.example:target/);
    assert.match(displayed, /desired enabled; running state unavailable/);
    assert.match(displayed, /1 SMB share\(s\), 1 NFS export\(s\)/);
    assert.match(displayed, /Review potential backing-file exposure/);
    assert.match(displayed, /Zero configured overlaps does not prove isolation/);
    assert.doesNotMatch(displayed, /private-user|private-ref|11111111-2222|Private share name|198\.51\.100\.1/);
    await clickVisible("iscsi-draft-toggle");
    for (const [name, value] of Object.entries(iscsiDraftFieldsFixture())) {
      if (["mode", "target-id", "block-size", "allocation", "access", "auth", "target-user", "target-secret-ref"].includes(name)) continue;
      await clickVisible(`iscsi-draft-${name}`);
      await replaceInput(`iscsi-draft-${name}`, value);
    }
    await clickVisible("iscsi-draft-add");
    await until(() => evaluate(`document.getElementById('iscsi-status').textContent.includes('draft only') && !document.getElementById('iscsi-draft-add').disabled`), browser, "actual guided iSCSI candidate HTTP validation");
    const draft = JSON.parse(await evaluate("document.getElementById('iscsi-document').value"));
    assert.equal(draft.revision, 2); assert.equal(draft.iscsi.targets.length, 2);
    assert.deepEqual(draft.iscsi.targets[0], iscsiExposurePolicyFixture().iscsi.targets[0]);
    assert.equal(draft.iscsi.targets[1].state, "disabled");
    assert.equal(draft.iscsi.targets[1].initiators[0].authentication.initiator_secret_ref, "draft-secret");
    assert.match(await evaluate("document.getElementById('iscsi-result').textContent"), /desired disabled/);
    assert.doesNotMatch(await evaluate("document.getElementById('iscsi-result').textContent"), /draft-user|draft-secret/);
    // Extend via actual keyboard events without increasing the original32
    // pointer-action cap. Selecting a disabled draft is not runtime admission.
    await clickVisible("iscsi-draft-target-id");
    await key("Tab", "Tab", 9, 8);
    assert.equal(await evaluate("document.activeElement.id"), "iscsi-draft-mode");
    await key("ArrowDown", "ArrowDown", 40);
    assert.equal(await evaluate("document.getElementById('iscsi-draft-mode').value"), "existing-target");
    await key("Tab", "Tab", 9);
    await replaceInput("iscsi-draft-target-id", draft.iscsi.targets[1].id);
    for (let i = 0; i < 3; i++) await key("Tab", "Tab", 9);
    await replaceInput("iscsi-draft-path", "luns/draft-extra.img");
    for (let i = 0; i < 18 && await evaluate("document.activeElement.id") !== "iscsi-draft-add"; i++) await key("Tab", "Tab", 9);
    assert.equal(await evaluate("document.activeElement.id"), "iscsi-draft-add");
    await key("Enter", "Enter", 13);
    await until(() => evaluate(`document.getElementById('iscsi-status').textContent.includes('draft only') && !document.getElementById('iscsi-draft-add').disabled`), browser, "actual disabled-target LUN extension HTTP validation");
    const extended = JSON.parse(await evaluate("document.getElementById('iscsi-document').value"));
    assert.equal(extended.revision, 3); assert.equal(extended.iscsi.targets.length, 2);
    assert.deepEqual(extended.iscsi.targets[0],draft.iscsi.targets[0]);
    assert.deepEqual(extended.iscsi.targets[1].luns[0],draft.iscsi.targets[1].luns[0]);
    assert.equal(extended.iscsi.targets[1].luns[1].number, 1);
    assert.equal(extended.iscsi.targets[1].initiators.length, 1);
    assert.deepEqual(extended.iscsi.targets[1].initiators[0].authentication,draft.iscsi.targets[1].initiators[0].authentication);
    assert.deepEqual(extended.iscsi.targets[1].initiators[0].grants[0],draft.iscsi.targets[1].initiators[0].grants[0]);
    assert.equal(extended.iscsi.targets[1].initiators[0].grants.length, 2);
    for (const width of [1365, 390, 320]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      await evaluate("document.getElementById('iscsi-result').scrollIntoView({block:'start'})");
      assert.equal(await evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), true, "iSCSI result overflow");
      const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      assert.ok(shot.data.length <= 8 * 1024 * 1024);
      await writeFile(join(artifacts, `iscsi-${width}.png`), Buffer.from(shot.data, "base64"));
      await evaluate("document.getElementById('iscsi-draft-fields').scrollIntoView({block:'start'})");
      assert.equal(await evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), true, "guided iSCSI fields overflow");
      const formShot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      assert.ok(formShot.data.length <= 8 * 1024 * 1024);
      await writeFile(join(artifacts, `iscsi-draft-${width}.png`), Buffer.from(formShot.data, "base64"));
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
    await clickVisible("iscsi-draft-target-id");
    await key("Tab", "Tab", 9, 8); await key("ArrowUp", "ArrowUp", 38);
    assert.equal(await evaluate("document.getElementById('iscsi-draft-mode').value"), "new-target");
    await key("Tab", "Tab", 9);
    assert.equal(await evaluate("document.activeElement.id"), "iscsi-draft-target-id");
    await key("a", "KeyA", 65, 2); await key("Backspace", "Backspace", 8);
    const duplicateBase = JSON.stringify(iscsiExposurePolicyFixture()).replace('"revision":1', '"revision":1,"revision":1');
    await clickVisible("iscsi-document");
    await replaceInput("iscsi-document", duplicateBase);
    await clickVisible("iscsi-draft-add");
    await until(() => evaluate(`document.getElementById('iscsi-status').textContent.includes('could not be verified') && !document.getElementById('iscsi-draft-add').disabled`), browser, "strict original-policy refusal before candidate submission");
    assert.equal(await evaluate("document.getElementById('iscsi-document').value"), duplicateBase);
    assert.equal(await evaluate("document.getElementById('iscsi-result').hidden"), true);
    await clickVisible("iscsi-clear");
    assert.equal(await evaluate("document.getElementById('iscsi-document').value"), "");
    assert.equal(await evaluate("document.getElementById('iscsi-result').hidden"), true);
    for (const name of ["name", "path", "initiator", "chap-user", "secret-ref"]) assert.equal(await evaluate(`document.getElementById('iscsi-draft-${name}').value`), "");
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/iscsi/preview").length, 6);
  }

  if (networkMode) {
    const source = JSON.stringify(networkPolicyFixture()).replace('"revision":1', '"revision":18446744073709551615');
    await clickVisible("network-document");
    await replaceInput("network-document", source);
    await key("Tab", "Tab", 9);
    assert.equal(await evaluate("document.activeElement.id"), "network-submit");
    await key("Enter", "Enter", 13);
    await until(() => evaluate(`!document.getElementById('network-result').hidden && !document.getElementById('network-submit').disabled`), browser, "actual desired-network HTTP preview");
    const displayed = await evaluate("document.getElementById('network-result').textContent");
    assert.match(displayed, /18446744073709551615/);
    assert.match(displayed, /192\.0\.2\.10\/16/); assert.match(displayed, /fe80::1/);
    assert.match(displayed, /NOT SAVED \/ NOT APPLIED/); assert.match(displayed, /not a physical port mapping/);
    for (const width of [1365, 390, 320]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      await evaluate("document.getElementById('network-title').scrollIntoView()");
      assert.equal(await evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), true);
      const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      assert.ok(shot.data.length <= 8 * 1024 * 1024);
      await writeFile(join(artifacts, `network-preview-${width}.png`), Buffer.from(shot.data, "base64"));
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
    await clickVisible("network-document");
    await replaceInput("network-document", source.replace('"revision":18446744073709551615', '"revision":1,"revision":1'));
    await key("Tab", "Tab", 9); await key("Enter", "Enter", 13);
    await until(() => evaluate(`document.getElementById('network-status').textContent.includes('could not be verified') && !document.getElementById('network-submit').disabled`), browser, "strict desired-network refusal");
    assert.equal(await evaluate("document.getElementById('network-result').hidden"), true);
    await clickVisible("network-clear");
    assert.equal(await evaluate("document.getElementById('network-document').value"), "");
    await clickVisible("network-draft-toggle");
    const fields = networkDraftFieldsFixture();
    const edit = async (name, value) => {
      await clickVisible(`network-draft-${name}`);
      await replaceInput(`network-draft-${name}`, value);
    };
    await edit("revision", fields.revision);
    await edit("hostname", fields.hostname);
    await clickVisible("network-draft-lan-1-ipv4-mode");
    await key("ArrowDown", "ArrowDown", 40); await key("ArrowDown", "ArrowDown", 40); await key("Enter", "Enter", 13); await key("Tab", "Tab", 9);
    assert.equal(await evaluate("document.activeElement.id"), "network-draft-lan-1-ipv4-addresses");
    await replaceInput("network-draft-lan-1-ipv4-addresses", fields["lan-1-ipv4-addresses"]);
    await key("Tab", "Tab", 9); await replaceInput("network-draft-lan-1-ipv4-gateway", fields["lan-1-ipv4-gateway"]);
    await key("Tab", "Tab", 9); await replaceInput("network-draft-lan-1-ipv4-metric", fields["lan-1-ipv4-metric"]);
    await key("Tab", "Tab", 9); await key("ArrowDown", "ArrowDown", 40); await key("ArrowDown", "ArrowDown", 40); await key("Tab", "Tab", 9);
    await replaceInput("network-draft-lan-1-ipv6-addresses", fields["lan-1-ipv6-addresses"]);
    await key("Tab", "Tab", 9); await replaceInput("network-draft-lan-1-ipv6-gateway", fields["lan-1-ipv6-gateway"]);
    await key("Tab", "Tab", 9); await replaceInput("network-draft-lan-1-ipv6-metric", fields["lan-1-ipv6-metric"]);
    await clickVisible("network-draft-lan-2-ipv4-mode");
    await key("ArrowDown", "ArrowDown", 40); await key("Enter", "Enter", 13); await key("Tab", "Tab", 9);
    await clickVisible("network-draft-lan-2-ipv6-mode");
    await key("ArrowDown", "ArrowDown", 40); await key("Enter", "Enter", 13); await key("Tab", "Tab", 9);
    await clickVisible("network-draft-dns-source");
    await key("ArrowDown", "ArrowDown", 40); await key("Enter", "Enter", 13); await key("Tab", "Tab", 9);
    await edit("search-domains", fields["search-domains"]);
    await edit("routes", fields.routes);
    for (const [name, value] of Object.entries(fields)) {
      assert.equal(await evaluate(`document.getElementById('network-draft-${name}').value`), value, `actual guided field ${name}`);
    }
    await clickVisible("network-draft-build");
    await until(() => evaluate(`document.getElementById('network-status').textContent.includes('Guided proposal validated') && !document.getElementById('network-draft-build').disabled`), browser, "actual guided network HTTP validation");
    const guidedText = await evaluate("document.getElementById('network-document').value");
    assert.match(guidedText, /"revision":18446744073709551615,/);
    assert.deepEqual(JSON.parse(guidedText.replace('"revision":18446744073709551615', '"revision":1')), networkPolicyFixture());
    for (const width of [1365, 390, 320]) {
      await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
      await evaluate("document.getElementById('network-draft-fields').scrollIntoView({block:'start'})");
      assert.equal(await evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), true, `guided network page overflow at ${width}`);
      assert.equal(await evaluate("[...document.querySelectorAll('#network-draft-fields input, #network-draft-fields select, #network-draft-fields textarea')].every(e => e.getBoundingClientRect().width > 0 && e.getBoundingClientRect().right <= document.documentElement.clientWidth)"), true);
      const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
      assert.ok(shot.data.length <= 8 * 1024 * 1024);
      await writeFile(join(artifacts, `network-guided-${width}.png`), Buffer.from(shot.data, "base64"));
    }
    await send("Emulation.setDeviceMetricsOverride", { width: 1365, height: 900, deviceScaleFactor: 1, mobile: false });
    await clickVisible("network-draft-build");
    assert.match(await evaluate("document.getElementById('network-status').textContent"), /Confirm complete replacement/);
    assert.equal(await evaluate("document.getElementById('network-document').value"), guidedText);
    await key("Tab", "Tab", 9, 8);
    assert.equal(await evaluate("document.activeElement.id"), "network-draft-replace");
    await key(" ", "Space", 32);
    assert.equal(await evaluate("document.getElementById('network-draft-replace').checked"), true);
    await key("Tab", "Tab", 9); await key("Enter", "Enter", 13);
    await until(() => evaluate(`document.getElementById('network-status').textContent.includes('Guided proposal validated') && !document.getElementById('network-draft-build').disabled`), browser, "explicit guided replacement HTTP validation");
    assert.equal(await evaluate("document.getElementById('network-document').value"), guidedText);
    assert.equal(await evaluate("document.getElementById('network-draft-replace').checked"), false);
    await clickVisible("network-clear");
    for (const id of ["hostname", "routes", "lan-1-ipv4-addresses", "lan-1-ipv6-gateway"]) {
      assert.equal(await evaluate(`document.getElementById('network-draft-${id}').value`), "");
    }
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/network/preview").length, 4);
  }

  // Use actual browser keyboard dispatch, not HTMLElement.focus(), for Tab.
  await send("Page.navigate", { url: origin });
  await until(() => evaluate(snapshotReady), browser, "keyboard page load");
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
  await until(() => evaluate(snapshotReady), browser, "explicit browser refresh");
  assert.equal(cdp.requests.filter((r) => new URL(r.url).pathname === "/api/v1/system").length, before + 1);
  if (apiFixture && !serviceMode) {
    // Controlled401/status replies exercise the actual browser lifecycle;
    // logout/login and cookie revocation still use the real memory backend.
    // No desired-policy store or service activation is installed in the fixture.
    const servicePaused = cdp.paused.length;
    await send("Fetch.enable", { patterns: ["/api/v1/file-services/configuration", "/api/v1/auth/status"].map(path => ({
      urlPattern: origin + path, requestStage: "Request",
    })) });
    await evaluate("document.getElementById('service-load').click()");
    await until(() => cdp.paused.length === servicePaused + 1, browser, "controlled policy401 interception");
    await send("Fetch.fulfillRequest", { requestId: cdp.paused[servicePaused], responseCode: 401,
      responseHeaders: [{ name: "Content-Type", value: "application/json" }], body: Buffer.from("{}").toString("base64") });
    await until(() => cdp.paused.length === servicePaused + 2, browser, "original401 status interception");
    let retiredCookie = await currentCookie();
    assert.equal(await cookieStatus(retiredCookie), 200);
    await clickVisible("logout");
    await until(() => cdp.paused.length === servicePaused + 3, browser, "replacement logout status");
    await send("Fetch.continueRequest", { requestId: cdp.paused[servicePaused + 2] });
    await until(() => evaluate(signInReady), browser, "logout retires pending policy status");
    assert.equal(await cookieStatus(retiredCookie), 401, "real logout must revoke the prior cookie");
    retiredCookie = undefined;
    assert.equal(await evaluate("document.getElementById('support-download').disabled"), true);
    // Reuse the original wrong/correct-login leg instead of adding another
    // login cycle: the real five-attempt/minute limiter stays unchanged.
    await submitLogin("browser fixture intentionally wrong passphrase");
    await until(() => evaluate(`!document.getElementById('auth-error').hidden && document.getElementById('auth-error').textContent === 'The username or password is not correct.' && !document.getElementById('auth-submit').disabled`), browser, "wrong-password refusal");
    assert.equal(await evaluate("document.getElementById('dashboard-content').hidden"), true);
    await submitLogin(fixturePassword);
    await until(() => cdp.paused.length === servicePaused + 4, browser, "replacement login status");
    await send("Fetch.continueRequest", { requestId: cdp.paused[servicePaused + 3] });
    await until(() => evaluate(snapshotReady), browser, "replacement authenticated view");
    // An aborted interception may no longer accept a reply. If it does, the
    // old continuation must still have no view authority.
    await send("Fetch.fulfillRequest", { requestId: cdp.paused[servicePaused + 1], responseCode: 200,
      responseHeaders: [{ name: "Content-Type", value: "application/json" }],
      body: Buffer.from(JSON.stringify({ authenticated: false, setup_required: false })).toString("base64") }).catch(() => {});
    await send("Fetch.disable");
    await evaluate("new Promise(resolve => setTimeout(resolve, 0))");
    assert.equal(await evaluate(snapshotReady), true, "retired policy status overwrote a replacement login");
    assert.equal(await evaluate("document.getElementById('service-load').disabled"), false);
    assert.equal(await cookieStatus(await currentCookie()), 200);
    let oldCookie = await currentCookie();
    assert.equal(await cookieStatus(oldCookie), 200);
    await changePassword(fixturePassword, nextPassword);
    await until(() => evaluate(`${signInReady} && document.getElementById('auth-error').textContent === 'Password changed. All panel sessions ended. Sign in with the new password.'`), browser, "actual password replacement");
    assert.equal(await cookieStatus(oldCookie), 401, "password replacement did not revoke original cookie");
    assert.equal(await evaluate("['password-current', 'password-new', 'password-confirm'].every(id => document.getElementById(id).value === '')"), true);
    await submitLogin(fixturePassword);
    await until(() => evaluate(`!document.getElementById('auth-error').hidden && document.getElementById('auth-error').textContent === 'The username or password is not correct.' && !document.getElementById('auth-submit').disabled`), browser, "old-password refusal");
    await submitLogin(nextPassword);
    await until(() => evaluate(snapshotReady), browser, "replacement-password login");
    oldCookie = await currentCookie();
    assert.equal(await cookieStatus(oldCookie), 200);
    await clickVisible("logout-all");
    await until(() => evaluate(signInReady), browser, "global panel logout");
    assert.equal(await cookieStatus(oldCookie), 401, "global logout did not revoke original cookie");
    oldCookie = undefined;
    assert.equal(await evaluate("fetch('/api/v1/system').then(r => r.status)"), 401);
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/auth/setup" && r.method === "POST").length, 1);
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/auth/login" && r.method === "POST").length, 4);
    assert.equal(cdp.requests.filter(r => new URL(r.url).pathname === "/api/v1/auth/password" && r.method === "POST").length, 1);
    // Freeze one login before headers, while using the real browser's timer.
    // This is controlled network interception, not server-operation cancel proof.
    const credentialPaused = cdp.paused.length;
    await send("Fetch.enable", { patterns: [{ urlPattern: origin + "/api/v1/auth/login", requestStage: "Request" }] });
    await submitLogin(nextPassword);
    await until(() => cdp.paused.length === credentialPaused + 1, browser, "controlled credential interception");
    await until(() => evaluate(`document.getElementById('auth-form').hidden && !document.getElementById('auth-retry').hidden && document.getElementById('auth-error').textContent.includes('The request was not retried.')`), browser, "credential header deadline", 15000);
    assert.equal(await evaluate("document.getElementById('auth-submit').disabled"), false);
    assert.equal(await evaluate("document.getElementById('auth-password').value"), "");
    await send("Fetch.failRequest", { requestId: cdp.paused[credentialPaused], errorReason: "Aborted" }).catch(() => {});
    await send("Fetch.disable");
    await clickVisible("auth-retry");
    await until(() => evaluate(signInReady), browser, "explicit status-only reconciliation");
    assert.equal(cdp.paused.length, credentialPaused + 1, "credential request must not automatically retry");
    await submitLogin(nextPassword);
    await until(() => evaluate(snapshotReady), browser, "login for controlled mutation failures");
    for (const action of ["password", "logout-all"]) {
      const path = `/api/v1/auth/${action}`;
      const paused = cdp.paused.length;
      const posts = () => cdp.requests.filter(r => new URL(r.url).pathname === path && r.method === "POST").length;
      const before = posts();
      oldCookie = await currentCookie();
      await send("Fetch.enable", { patterns: [{ urlPattern: origin + path, requestStage: "Request" }] });
      if (action === "password") {
        await changePassword(nextPassword, "browser fixture intercepted third passphrase");
      } else await clickVisible("logout-all");
      await until(() => cdp.paused.length === paused + 1, browser, "controlled mutation interception");
      await until(() => evaluate(`document.getElementById('auth-form').hidden && !document.getElementById('auth-retry').hidden && document.getElementById('auth-error').textContent.includes('not retried')`), browser, "mutation header deadline", 15000);
      assert.equal(await evaluate("['password-submit', 'logout', 'logout-all'].every(id => !document.getElementById(id).disabled)"), true);
      assert.equal(await evaluate("['password-current', 'password-new', 'password-confirm'].every(id => document.getElementById(id).value === '')"), true);
      await send("Fetch.failRequest", { requestId: cdp.paused[paused], errorReason: "Aborted" }).catch(() => {});
      await send("Fetch.disable");
      // Interception deliberately prevents the mutation reaching the server:
      // the old cookie remains valid, so do not report confirmed revocation.
      assert.equal(await cookieStatus(oldCookie), 200);
      oldCookie = undefined;
      await clickVisible("auth-retry");
      await until(() => evaluate(snapshotReady), browser, "mutation status-only reconciliation");
      assert.equal(posts(), before + 1, "uncertain mutation must not automatically retry");
    }
  }
  assert.equal(cdp.exceptions, 0, "uncaught page JavaScript exception");
  assert.ok(!cdp.fault, "browser protocol observation failed");
  let localInlineImages = 0;
  for (const request of cdp.requests) if (classifyPageResource(request, origin, Boolean(apiFixture), serviceMode) === "local-inline-image") localInlineImages++;
  assert.ok(live(preview), "owned preview exited during browser verification");
  assert.ok(!previewErrorOutput, "owned fixture wrote an unexpected error");
  assert.deepEqual(await uiHashes(), sourceHashes, "dashboard source changed during browser verification");
  assert.deepEqual(await harnessHashes(), harnessSourceHashes, "browser harness changed during verification");
  result = {
    schema_version: 1, scope, browser: version.product,
    ui_sha256: sourceHashes, harness_sha256: harnessSourceHashes,
    layouts, keyboard_skip_link: true, explicit_refresh: true, page_requests: cdp.requests.length,
    uncaught_exceptions: cdp.exceptions, actual_go_auth_memory_fixture: Boolean(apiFixture),
    original_cookie_revocation_checked: Boolean(apiFixture && !serviceMode), authentication_qualified: false, hardware_qualified: false,
    intercepted_credential_deadline: Boolean(apiFixture && !serviceMode),
    intercepted_auth_mutation_deadlines: apiFixture && !serviceMode ? ["password", "logout-all"] : [],
    retired_service401_recheck: Boolean(apiFixture && !serviceMode),
    visible_pointer_controls: pointerControls,
    auth_keyboard_tab_enter: Boolean(apiFixture),
    iscsi_preview_actual_http: Boolean(apiFixture && !networkMode && !serviceMode),
    iscsi_guided_draft_actual_http: Boolean(apiFixture && !networkMode && !serviceMode),
    iscsi_guided_base_refusal_actual_http: Boolean(apiFixture && !networkMode && !serviceMode),
    iscsi_guided_lun_extension_actual_http: Boolean(apiFixture && !networkMode && !serviceMode),
    service_policy_actual_http: servicePolicyResult ?? null,
    network_preview_actual_http: networkMode,
    network_guided_draft_actual_http: networkMode,
    network_guided_replacement_consent: networkMode,
    network_base_refusal_actual_http: networkMode,
    local_inline_images: localInlineImages,
    same_origin_network_requests: cdp.requests.length - localInlineImages,
  };
  successful = true;
} catch (error) {
  failure = error;
} finally {
  clearTimeout(deadline);
  const cleanupErrors = [];
  try {
    if (cdp) {
      // Browser.close may close the socket before acknowledging the command.
      await cdp.send("Browser.close").catch(() => {});
    }
    for (const child of children.toReversed()) {
      try {
        if (live(child)) {
          // The preview intentionally runs until signaled; it needs no idle wait.
          if (child.isAPIFixture) {
            child.stdin.end(Buffer.from([4]));
            assert.ok(await settled(child, 5000), "API fixture did not acknowledge stop");
          } else if (!child.isBrowser) child.kill();
          else if (!await settled(child, 3000) && live(child)) child.kill();
        }
        assert.ok(await settled(child, 5000), "owned process did not stop");
        if (child.isAPIFixture) {
          assert.equal(child.exitCode, 0, "API fixture failed");
          assert.ok(child.stopVerified(), "API fixture disposal receipt missing");
        }
      } catch (error) {
        cleanupErrors.push(error);
        // A failed graceful disposal remains a failure even if forced stop
        // succeeds; nevertheless attempt to release every owned process.
        if (live(child)) child.kill();
        if (!await settled(child, 5000)) cleanupErrors.push(new Error("owned process forced stop unconfirmed"));
      }
    }
    if (profile) {
      assert.ok(children.every(child => !live(child)), "profile still has a live owner");
      // Validate this exact owned target before any Windows recursive removal.
      assert.equal(dirname(resolve(profile)), tempRoot, "profile escaped temporary root");
      assert.ok(basename(profile).startsWith("phantowd-dashboard-browser-"));
      assert.ok(!(await lstat(profile)).isSymbolicLink(), "profile became a link");
      await rm(profile, { recursive: true });
    }
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (cleanupErrors.length) failure = new AggregateError([failure, ...cleanupErrors].filter(Boolean), "browser verification or cleanup failed");
}
if (failure) {
  await writeFile(join(artifacts, "result.json"), JSON.stringify({
    schema_version: 1, status: "failed", scope, ui_sha256: sourceHashes, harness_sha256: harnessSourceHashes,
  }, null, 2) + "\n");
  throw failure;
}
assert.ok(successful, "browser test did not finish");
await writeFile(join(artifacts, "result.json"), JSON.stringify({ ...result, status: "passed", owned_profile_removed: true }, null, 2) + "\n");
console.log(`PHANTOWD_DASHBOARD_BROWSER_READY scope=${scope} viewports=3 keyboard=skip-link`);
