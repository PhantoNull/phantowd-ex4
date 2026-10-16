// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Dependency-free browser-DOM smoke tests for the embedded dashboard logic.
// This does not claim visual browser or assistive-technology coverage.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, Script } from "node:vm";
import { supportFixture } from "./tests/test-support-bundle.mjs";
import { testISCSIPanel } from "./tests/test-iscsi-panel.mjs";
import { testNetworkPanel } from "./tests/test-network-panel.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = await readFile(join(repoRoot, "src/phantowd-api/ui/app.js"), "utf8");
const authSource = await readFile(join(repoRoot, "src/phantowd-api/ui/auth.js"), "utf8");
const serviceSource = await readFile(join(repoRoot, "src/phantowd-api/ui/service-policy.js"), "utf8");
const supportSource = await readFile(join(repoRoot, "src/phantowd-api/ui/support-bundle.js"), "utf8");
const iscsiSource = await readFile(join(repoRoot, "src/phantowd-api/ui/iscsi-preview.js"), "utf8");
const networkSource = await readFile(join(repoRoot, "src/phantowd-api/ui/network-preview.js"), "utf8");
const markup = await readFile(join(repoRoot, "src/phantowd-api/ui/index.html"), "utf8");
const styles = await readFile(join(repoRoot, "src/phantowd-api/ui/app.css"), "utf8");
assert.ok(markup.indexOf('<script src="/assets/auth.js" defer>') > markup.indexOf('<script src="/assets/app.js" defer>'), "auth module must load after its shared UI helpers");
assert.ok(markup.indexOf('<script src="/assets/iscsi-preview.js" defer>') > markup.indexOf('<script src="/assets/app.js" defer>'));
assert.ok(markup.indexOf('<script src="/assets/auth.js" defer>') > markup.indexOf('<script src="/assets/iscsi-preview.js" defer>'));
assert.ok(markup.indexOf('<script src="/assets/network-preview.js" defer>') > markup.indexOf('<script src="/assets/app.js" defer>'));
assert.ok(markup.indexOf('<script src="/assets/auth.js" defer>') > markup.indexOf('<script src="/assets/network-preview.js" defer>'));
assert.ok(authSource.includes("updateAuthView().catch(showAuthUnavailable)"));
assert.ok(!source.includes("updateAuthView().catch(showAuthUnavailable)"), "only the auth module starts authentication");
assert.doesNotMatch(source + authSource + serviceSource + iscsiSource + networkSource, /\.json\s*\(/, "Merged dashboard consumers must retain bounded response readers");
assert.doesNotMatch(iscsiSource + networkSource, /\.(?:innerHTML|outerHTML)\b/);
for (const name of ["setAuthError", "showAuthUnavailable", "updateAuthView", "signOut", "clearPasswordFields"]) {
  assert.ok(!source.includes(`function ${name}(`), "The merge must not resurrect retired authentication handlers in app.js");
  assert.ok(authSource.includes(`function ${name}(`));
}
for (const name of ["index.html", "app.css", "app.js", "auth.js", "service-policy.js", "support-bundle.js", "iscsi-preview.js", "network-preview.js", "ghost.svg"]) {
  assert.ok((await readFile(join(repoRoot, "src/phantowd-api/ui", name))).byteLength <= 65536, "per-asset budget must not grow");
}
const markupIDs = [...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
assert.equal(new Set(markupIDs).size, markupIDs.length, "duplicate HTML IDs");
for (const match of (source + authSource + serviceSource + iscsiSource + networkSource).matchAll(/(?:byId|setText)\("([^"]+)"/g)) {
  assert.ok(markupIDs.includes(match[1]), `script references missing HTML ID ${match[1]}`);
}
assert.match(markup, /id="policy-nfs-fields"[^>]*hidden disabled/);
assert.match(markup, /id="policy-form"[^>]*autocomplete="off"/);
assert.match(markup, /id="service-editor"[^>]*aria-describedby="service-user-help"/);
assert.ok(markup.indexOf('id="service-user-help"') < markup.indexOf('id="service-editor"'), "long reference guidance belongs outside the two-column editor grid");
assert.match(markup, /<body>\s*<a class="skip-link" id="skip-to-content" href="#main-content">Skip to main content<\/a>/);
assert.match(markup, /<main id="main-content" tabindex="-1">/);
for (const id of ["auth-title", "page-title"]) {
  assert.match(markup, new RegExp(`<h1 id="${id}" tabindex="-1">`));
}
assert.match(styles, /:is\(a, button, input, select, textarea, summary, \[tabindex\]\):focus-visible\s*\{\s*outline: 2px solid var\(--violet\);\s*outline-offset: 3px;/);
assert.match(styles, /\.skip-link:focus\s*\{ transform: none; \}/);
assert.match(styles, /@media \(forced-colors: active\)/);

// Numeric guard for the small secondary text palette, not a browser/CSS
// cascade or whole-page accessibility audit. Read the actual embedded asset.
// WCAG 2.2 1.4.3: https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html
function luminance(rgb) {
  const linear = rgb.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => a - b);
  return (values[1] + 0.05) / (values[0] + 0.05);
}

function blend(foreground, background, alpha) {
  return foreground.map((channel, index) => channel * alpha + background[index] * (1 - alpha));
}

function secondaryTextPalette(css) {
  const root = css.match(/:root\s*\{([^}]+)\}/)?.[1];
  assert.ok(root, "embedded stylesheet must declare its palette");
  const colors = new Map([...root.matchAll(/--([\w-]+):\s*#([\da-f]{6})\s*;/gi)]
    .map((match) => [match[1], match[2].match(/../g).map((channel) => parseInt(channel, 16))]));
  for (const name of ["quiet", "canvas", "surface", "surface-raised"]) {
    assert.ok(colors.has(name), `missing opaque palette color ${name}`);
  }
  return colors;
}

assert.equal(contrast([0, 0, 0], [255, 255, 255]), 21);
assert.equal(contrast([127, 127, 127], [127, 127, 127]), 1);
const textPalette = secondaryTextPalette(styles);
for (const name of ["canvas", "surface", "surface-raised"]) {
  const ratio = contrast(textPalette.get("quiet"), textPalette.get(name));
  assert.ok(ratio >= 4.5, `secondary text on ${name}: ${ratio}:1 is below 4.5:1`);
}
// Guard the declared maximum stops; this does not emulate gradient rendering.
assert.match(styles, /rgb\(255 255 255 \/ 2%\)/);
assert.match(styles, /rgb\(112 86 187 \/ 16%\)/);
for (const [name, background] of [
  ["card highlight", blend([255, 255, 255], textPalette.get("surface"), 0.02)],
  ["canvas highlight", blend([112, 86, 187], textPalette.get("canvas"), 0.16)],
]) {
  const ratio = contrast(textPalette.get("quiet"), background);
  assert.ok(ratio >= 4.5, `secondary text on ${name}: ${ratio}:1 is below 4.5:1`);
}

class FixtureElement {
  constructor(ownerDocument = null) {
    this.ownerDocument = ownerDocument;
    this.attributes = new Map();
    this.children = [];
    this.dataset = {};
    this.hidden = false;
    this.listeners = new Map();
    this.style = {};
    this.textContent = "";
    this.value = "";
    this.className = "";
    this.disabled = false;
    this.files = [];
    this.parentElement = null;
    this.classList = {
      toggle: (name, force) => {
        const classes = new Set(this.className.split(/\s+/).filter(Boolean));
        const enabled = force ?? !classes.has(name);
        if (enabled) classes.add(name);
        else classes.delete(name);
        this.className = [...classes].join(" ");
        return enabled;
      },
    };
  }

  addEventListener(name, handler) {
    this.listeners.set(name, handler);
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes) {
    this.children = [...nodes];
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  click() {
    if (this.download && !this.disabled) this.ownerDocument.downloads.push({ href: this.href, filename: this.download });
  }

  remove() {
    this.ownerDocument.body.children = this.ownerDocument.body.children.filter((node) => node !== this);
  }

  contains(node) {
    for (let current = node; current; current = current.parentElement) {
      if (current === this) return true;
    }
    return false;
  }

  get hidden() { return this.isHidden; }

  set hidden(value) {
    this.isHidden = value;
    // Model focus retirement before testing the actual source's replacement.
    if (value && this.ownerDocument && this.contains(this.ownerDocument.activeElement)) {
      this.ownerDocument.activeElement = this.ownerDocument.body;
    }
  }

  focus(options) {
    if (!this.ownerDocument || this.disabled) return;
    for (let current = this; current; current = current.parentElement) {
      if (current.hidden) return;
    }
    this.ownerDocument.activeElement = this;
    this.ownerDocument.focusCalls.push({ element: this, options });
  }
}

function jsonResponse(body, status = 200) {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  return { ok: status >= 200 && status < 300, status, json: async () => body,
    body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }) };
}

function deferredJSONResponse(body) {
  let sent = false;
  return { ok: true, status: 200, json: () => body,
    body: { getReader: () => ({
      read: async () => sent ? { done: true } : (sent = true, { done: false, value: new TextEncoder().encode(JSON.stringify(await body)) }),
      cancel: async () => {}, releaseLock: () => {},
    }) } };
}

function systemFixture() {
  return {
    schema_version: 1,
    target: "qemu-armv5",
    mode: "development",
    flashable: false,
    hardware_validated: false,
    observed_at: "2026-09-25T12:30:00Z",
    architecture: "arm",
    goarm: "5",
    kernel: "6.18.54",
    uptime_seconds: 123456,
    memory: { total_bytes: 256 * 1024 * 1024, available_bytes: 96 * 1024 * 1024 },
  };
}

function arraysFixture() {
  return {
    schema_version: 1, read_only: true, block_devices_opened: false,
    disk_content_read: false, mutations_performed: false,
    status: "available",
    array_count: 2,
    arrays: [{
      name: "md0", level: "raid1", state: "clean", health: "healthy",
      expected_devices: 2, active_devices: 2, degraded_devices: 0,
      sync_action: "idle", members: [{ name: "sda2" }, { name: "sdb2" }],
    }, {
      name: "md1", level: "raid1", state: "active", health: "paused",
      expected_devices: 2, active_devices: 2, degraded_devices: 0,
      sync_action: "frozen", members: [{ name: "sda3" }, { name: "sdb3" }],
    }],
  };
}

function storageFixture(observations = []) {
  return {
    schema_version: 2, scope: "kernel-sysfs-only", inventory_read_only: true,
    block_devices_opened: false, content_read: false, mutations_performed: false,
    stable_identity_available: false, device_count: observations.length,
    observations, limitations: [],
  };
}

function blockFixture(overrides = {}) {
  return { name: "sda", kind: "block", major: 8, minor: 0, size_bytes: 2 ** 40,
    read_only: false, removable: false, serial_status: "present", wwn_status: "unavailable", ...overrides };
}

function mountsFixture() {
  return {
    schema_version: 1,
    scope: "current-process-mount-namespace",
    read_only: true,
    filesystem_contents_read: false,
    mount_operations_performed: false,
    mount_count: 2,
    mounts: [
      { mount_point: "/mnt/data<script>", filesystem: "ext4", device_major: 8, device_minor: 1, read_only: false },
      { mount_point: "/proc", filesystem: "proc", device_major: 0, device_minor: 42, read_only: true },
    ],
  };
}

async function createHarness(respond, timing = {}) {
  const ids = [
    "main-content", "page-title", "skip-to-content",
    "auth-panel", "auth-title", "auth-description", "auth-form", "auth-username",
    "auth-password", "auth-submit", "auth-retry", "auth-error", "dashboard-content",
    "logout", "logout-all", "refresh", "refresh-label", "snapshot-status", "snapshot-age", "error-banner",
    ...["panel", "form", "current", "new", "confirm", "submit", "status"].map((id) => `password-${id}`),
    "service-status-dot", "build-label", "kernel-value", "runtime-value", "target-value",
    "memory-value", "memory-detail", "memory-meter", "firmware-value", "firmware-detail",
    "profile-notice-title", "profile-notice-copy", "profile-notice-mark",
    "observed-at", "device-count", "device-list", "array-count", "array-list", "mount-count", "mount-list",
    "gpt-observe", "gpt-observation-status",
    "support-panel", "support-help", "support-download", "support-status",
    ...["form", "document", "submit", "clear", "result", "status"].map(id => `iscsi-${id}`),
    ...["form", "document", "submit", "clear", "result", "status"].map(id => `network-${id}`),
    ...["fields", "add", "mode", "target-id", "name", "volume", "path", "capacity", "block-size", "allocation", "access", "initiator", "auth", "chap-user", "secret-ref", "target-user", "target-secret-ref"].map(id => `iscsi-draft-${id}`),
    ...["load", "status", "result", "summary", "shares"].map((id) => `saved-${id}`),
    ...["load", "prepare", "save", "status", "current", "summary", "document", "review", "change", "samba", "nfs", "editor", "target", "member", "action", "edit-preview", "diff", "diff-summary", "overlaps", "overlap-summary", "backup-controls", "backup-download", "restore-file", "restore-preview"].map((id) => `service-${id}`),
    ...["form", "submit", "clear", "result", "error", "status", "requirements", "samba", "nfs", "nfs-fields", "uuid", "name", "path", "user", "smb-access", "nfs-enabled", "export-id", "network", "nfs-access", "squash", "uid", "gid", "security"].map((id) => `policy-${id}`),
  ];
  const document = { activeElement: null, focusCalls: [], downloads: [], blobs: [], revokedURLs: [] };
  const elements = Object.fromEntries(ids.map((id) => [id, new FixtureElement(document)]));
  document.body = new FixtureElement(document);
  document.activeElement = document.body;
  elements["main-content"].parentElement = document.body;
  elements["auth-panel"].parentElement = elements["main-content"];
  elements["dashboard-content"].parentElement = elements["main-content"];
  for (const [id, element] of Object.entries(elements)) {
    if (["main-content", "auth-panel", "dashboard-content"].includes(id)) continue;
    element.parentElement = id === "logout" || id === "skip-to-content" ? document.body :
      id.startsWith("auth-") ? elements["auth-panel"] : elements["dashboard-content"];
  }
  for (const id of ["auth-username", "auth-password", "auth-submit"]) {
    elements[id].parentElement = elements["auth-form"];
  }
  elements["refresh-label"].textContent = "Refresh snapshot";
  elements["memory-meter"].parentElement = new FixtureElement();
  Object.assign(document, {
    getElementById: (id) => elements[id] ?? null,
    createElement: () => new FixtureElement(document),
    createTextNode: (text) => ({ textContent: String(text) }),
  });
  const requests = [];
  const fetch = async (path, options) => {
    requests.push({ path, options });
    const result = await respond(path, options);
    if (result instanceof Error) throw result;
    return result;
  };
  const ageIntervals = new Map();
  let nextAgeInterval = 0;
  const context = createContext({
    document,
    fetch,
    Intl,
    Date: timing.Date ?? Date,
    performance: timing.performance ?? { now: () => 0 },
    Number,
    String,
    Math,
    Array,
    Error,
    Promise,
    TextEncoder,
    TextDecoder,
    Blob,
    URL: {
      createObjectURL: (blob) => { document.blobs.push(blob); return `blob:fixture-${document.blobs.length}`; },
      revokeObjectURL: (url) => document.revokedURLs.push(url),
    },
    AbortController,
    setTimeout: timing.setTimeout ?? setTimeout,
    clearTimeout: timing.clearTimeout ?? clearTimeout,
    setInterval: (callback, delay) => {
      const id = ++nextAgeInterval; ageIntervals.set(id, { callback, delay }); return id;
    },
    clearInterval: (id) => ageIntervals.delete(id),
  });
  new Script(serviceSource).runInContext(context);
  new Script(supportSource).runInContext(context);
  new Script(source).runInContext(context);
  new Script(iscsiSource).runInContext(context);
  new Script(networkSource).runInContext(context);
  new Script(authSource).runInContext(context);
  await new Promise((resolve) => setImmediate(resolve));
  return { context, elements, requests, document, ageIntervals };
}

async function testSnapshotLoadAgeUsesOnlyBrowserElapsedTime() {
  let now = 1000;
  let wall = 1700000000000;
  class WallClock extends Date { static now() { return wall; } }
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ?
    jsonResponse({ authenticated: true }) : snapshotResponse(path), {
    performance: { now: () => now }, Date: WallClock,
  });
  assert.equal(h.elements["snapshot-age"].textContent, "Snapshot loaded just now.");
  assert.equal(h.ageIntervals.size, 1);
  const timer = [...h.ageIntervals.values()][0];
  assert.equal(timer.delay, 30000);
  const before = h.requests.length;
  for (const [elapsed, label] of [[60000, "1 minute"], [120000, "2 minutes"],
    [3600000, "1 hour"], [86400000, "1 day"]]) {
    now = 1000 + elapsed; wall -= 123456789;
    timer.callback();
    assert.equal(h.elements["snapshot-age"].textContent, `Snapshot loaded ${label} ago.`);
  }
  assert.equal(h.requests.length, before, "Age updates must not poll the API or disks");
}

async function testSnapshotLoadAgeRefusesInvalidOrRegressingClock() {
  const respond = async (path) => path === "/api/v1/auth/status" ?
    jsonResponse({ authenticated: true }) : snapshotResponse(path, "clock-fixture");
  for (const now of [NaN, Infinity, -1, Number.MAX_SAFE_INTEGER + 1, null]) {
    const h = await createHarness(respond, {
      performance: { now: () => { if (now === null) throw new Error("clock failed"); return now; } },
    });
    assert.equal(h.elements["kernel-value"].textContent, "Linux clock-fixture", "Clock failure must not erase valid observations");
    assert.equal(h.elements["snapshot-age"].textContent, "Snapshot load age unavailable. Refresh to reset the clock.");
    assert.equal(h.ageIntervals.size, 0);
  }
  let now = 1000;
  const h = await createHarness(respond, { performance: { now: () => now } });
  const tick = [...h.ageIntervals.values()][0].callback;
  now = 121000; tick();
  now = 61000; tick();
  assert.match(h.elements["snapshot-age"].textContent, /age unavailable/);
  assert.equal(h.ageIntervals.size, 0);
  now = 181000; tick();
  assert.match(h.elements["snapshot-age"].textContent, /age unavailable/, "A retired clock must not recover without refresh");
}

async function testSnapshotAgeLifecycleAndPartialResults() {
  let now = 0;
  let authenticated = true;
  let failures = new Set();
  let pending = null;
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/logout") { authenticated = false; return jsonResponse({ logged_out: true }); }
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/auth/status") return jsonResponse({ configured: true, authenticated });
    if (pending) await pending;
    return failures.has(path) ? jsonResponse({}, 503) : snapshotResponse(path);
  }, { performance: { now: () => now } });
  const retired = [...h.ageIntervals.values()][0].callback;
  let release;
  pending = new Promise((resolve) => { release = resolve; });
  const loading = h.elements.refresh.listeners.get("click")();
  assert.equal(h.elements["snapshot-age"].textContent, "No loaded snapshot.");
  assert.equal(h.ageIntervals.size, 0, "Refresh must retire the prior age watcher");
  now = 60000; retired();
  assert.equal(h.elements["snapshot-age"].textContent, "No loaded snapshot.");
  pending = null; release(); await loading;
  assert.equal(h.ageIntervals.size, 1);
  assert.equal(h.elements["snapshot-age"].textContent, "Snapshot loaded just now.");
  retired();
  assert.equal(h.elements["snapshot-age"].textContent, "Snapshot loaded just now.");
  failures = new Set(["/api/v1/storage"]);
  await h.elements.refresh.listeners.get("click")();
  assert.equal(h.ageIntervals.size, 1, "A partial snapshot owns only one local watcher");
  assert.match(h.elements["snapshot-status"].textContent, /storage observation unavailable/);
  const tick = [...h.ageIntervals.values()][0].callback;
  h.document.hidden = true; now += 120000; tick();
  assert.equal(h.elements["snapshot-age"].textContent, "Snapshot loaded just now.");
  h.document.hidden = false; tick();
  assert.equal(h.elements["snapshot-age"].textContent, "Snapshot loaded 2 minutes ago.");
  failures = new Set(["/api/v1/system", "/api/v1/storage", "/api/v1/arrays", "/api/v1/mounts"]);
  await h.elements.refresh.listeners.get("click")();
  assert.equal(h.ageIntervals.size, 0);
  assert.equal(h.elements["snapshot-age"].textContent, "No loaded snapshot.");
  tick();
  assert.equal(h.elements["snapshot-age"].textContent, "No loaded snapshot.");
  failures.clear();
  await h.elements.refresh.listeners.get("click")();
  const beforeLogout = [...h.ageIntervals.values()][0].callback;
  await h.elements.logout.listeners.get("click")();
  assert.equal(h.ageIntervals.size, 0);
  now += 60000; beforeLogout();
  assert.equal(h.elements["snapshot-age"].textContent, "No loaded snapshot.");
  assert.equal(h.elements["dashboard-content"].hidden, true);
}

async function testAuthFocusMovesOnlyWhenItsControlIsHidden() {
  for (const setup of [false, true]) {
    let authenticated = false;
    const h = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated, setup_required: setup });
      if (path === (setup ? "/api/v1/auth/setup" : "/api/v1/auth/login")) {
        authenticated = true;
        return jsonResponse({ authenticated: true });
      }
      return snapshotResponse(path);
    });
    assert.ok(h.document.activeElement === h.document.body, "initial status must not steal focus");
    h.elements["auth-username"].value = "fixture-admin";
    h.elements["auth-password"].value = "public fixture passphrase";
    h.elements["auth-submit"].focus();
    await h.elements["auth-form"].listeners.get("submit")({ preventDefault() {} });
    assert.ok(h.document.activeElement === h.elements["page-title"], "hidden login/setup control loses focus without a visible destination");
    assert.equal(h.document.focusCalls.at(-1).options.preventScroll, true);

    h.elements.refresh.focus();
    const calls = h.document.focusCalls.length;
    await h.context.updateAuthView();
    assert.ok(h.document.activeElement === h.elements.refresh, "same-view refresh must not steal focus");
    assert.equal(h.document.focusCalls.length, calls);

    authenticated = false;
    await h.context.updateAuthView({ refresh: false, notice: "Session expired." });
    assert.ok(h.document.activeElement === h.elements["auth-title"], "expired session must leave focus in visible authentication view");
    h.elements["auth-password"].focus();
    await h.context.updateAuthView({ refresh: false });
    assert.ok(h.document.activeElement === h.elements["auth-password"], "unchanged login view must retain field focus");
    h.context.showAuthUnavailable();
    assert.ok(h.document.activeElement === h.elements["auth-title"], "hidden authentication field must not retain focus");
    h.elements["auth-retry"].focus();
    h.context.showAuthUnavailable();
    assert.ok(h.document.activeElement === h.elements["auth-retry"], "visible retry control must retain focus");
    await h.context.updateAuthView({ refresh: false });
    assert.ok(h.document.activeElement === h.elements["auth-title"], "hidden retry control must return focus to authentication heading");
  }

  for (const all of [false, true]) {
    let authenticated = true;
    const h = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated });
      if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
      if (path === (all ? "/api/v1/auth/logout-all" : "/api/v1/auth/logout")) {
        authenticated = false;
        return jsonResponse(all ? { all_panel_sessions_revoked: true } : { logged_out: true });
      }
      return snapshotResponse(path);
    });
    h.elements[all ? "logout-all" : "logout"].focus();
    await h.elements[all ? "logout-all" : "logout"].listeners.get("click")();
    assert.equal(h.elements["support-download"].disabled, true, "sign-out must retire diagnostic export");
    assert.ok(h.document.activeElement === h.elements["auth-title"], "hidden logout control must return focus to authentication heading");
    assert.equal(h.requests.filter((r) => r.options?.method === "POST").length, 1, "focus handling must not add requests");
  }
}

async function testAuthFocusAfterPasswordChangeOrUncertainty() {
  for (const confirmed of [false, true]) {
    let authenticated = true;
    const h = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated });
      if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
      if (path === "/api/v1/auth/password") {
        authenticated = false;
        return confirmed ? jsonResponse({ password_changed: true, reauthentication_required: true, all_panel_sessions_revoked: true }) :
          jsonResponse({ error: "unconfirmed" }, 503);
      }
      return snapshotResponse(path);
    });
    h.elements["password-current"].value = "old public fixture passphrase";
    h.elements["password-new"].value = "new public fixture passphrase";
    h.elements["password-confirm"].value = h.elements["password-new"].value;
    h.elements["password-submit"].focus();
    await h.elements["password-form"].listeners.get("submit")({ preventDefault() {} });
    assert.equal(h.elements["support-download"].disabled, true, "confirmed or uncertain password change must retire diagnostic export");
    assert.ok(h.document.activeElement === h.elements["auth-title"], "confirmed or uncertain credential boundary must have a visible focus destination");
    assert.equal(h.elements["auth-form"].hidden, !confirmed);
    assert.equal(h.requests.filter((r) => r.options?.method === "POST").length, 1, "focus handling must not retry password change");
  }
}

async function testAuthFocusDoesNotFollowRetiredOrUnrelatedReads() {
  let pending = false;
  let release;
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") {
      if (pending) return new Promise((resolve) => { release = resolve; });
      return jsonResponse({ authenticated: true });
    }
    return snapshotResponse(path);
  });
  h.elements.refresh.focus();
  pending = true;
  const retired = h.context.updateAuthView({ refresh: false, current: () => false });
  await settleUI();
  const calls = h.document.focusCalls.length;
  release(jsonResponse({ authenticated: false }));
  await retired;
  assert.ok(h.document.activeElement === h.elements.refresh);
  assert.equal(h.document.focusCalls.length, calls, "retired auth reply must not change focus");
  assert.equal(h.elements["dashboard-content"].hidden, false);

  h.elements["main-content"].focus();
  h.context.showAuthUnavailable();
  assert.ok(h.document.activeElement === h.elements["main-content"], "focus outside the disappearing controls must stay in place");
}

async function testReadOnlySnapshotAndSafeRendering() {
  const { context, elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") {
      return jsonResponse(storageFixture([blockFixture({ name: "disk<script>", read_only: true })]));
    }
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  assert.equal(elements["auth-panel"].hidden, true);
  assert.equal(elements["dashboard-content"].hidden, false);
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.54");
  assert.equal(elements["target-value"].textContent, "qemu-armv5");
  assert.match(elements["observed-at"].textContent, /^Last observed /);
  assert.equal(elements["observed-at"].dateTime, "2026-09-25T12:30:00.000Z");
  assert.equal(elements["profile-notice-title"].textContent, "Emulator only.");
  assert.match(elements["snapshot-status"].textContent, /updated/);
  assert.equal(elements["array-count"].textContent, "2 arrays");
  assert.equal(elements["array-list"].children[0].children[0].children[0].textContent, "md0");
  assert.equal(elements["array-list"].children[0].children[1].textContent, "healthy");
  assert.equal(elements["array-list"].children[1].children[1].textContent, "paused");
  assert.match(elements["array-list"].children[1].children[1].className, /array-health-paused/);
  assert.equal(elements["array-list"].children[1].children[4].textContent, "frozen · progress unavailable");
  assert.equal(elements["mount-count"].textContent, "2 mounts");
  assert.equal(elements["mount-list"].children[0].children[0].textContent, "/mnt/data<script>");
  assert.equal(elements["mount-list"].children[0].children[1].textContent, "ext4");
  assert.equal(elements["mount-list"].children[0].children[2].textContent, "8:1");
  assert.equal(elements["mount-list"].children[1].children[3].textContent, "Read-only mount flag");
  assert.equal(elements["device-list"].children[0].children[0].children[1].children[0].textContent, "disk<script>");
  assert.equal(elements["device-list"].children[0].children[3].textContent, "Kernel read-only");
  assert.deepEqual(requests.map(({ path }) => path), [
    "/api/v1/auth/status", "/api/v1/system", "/api/v1/storage", "/api/v1/arrays", "/api/v1/mounts",
  ]);
  assert.ok(requests.every(({ options }) => options.method === "GET"));

  elements["logout"].hidden = false;
  context.renderSystem({ ...systemFixture(), target: "ui-preview-fixture" });
  assert.equal(elements["build-label"].textContent, "LOCAL FIXTURES");
  assert.equal(elements["profile-notice-title"].textContent, "Synthetic preview.");
  assert.equal(elements["profile-notice-mark"].textContent, "FIXTURE DATA");
  assert.equal(elements["logout"].hidden, true);
}

async function testBrowserAuthFixtureKeepsVisibleRealAuthControls() {
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse({ ...systemFixture(), target: "browser-auth-fixture" });
    return snapshotResponse(path);
  });
  assert.equal(h.elements["profile-notice-title"].textContent, "Synthetic authentication fixture.");
  assert.equal(h.elements["profile-notice-mark"].textContent, "MEMORY-ONLY AUTH FIXTURE");
  assert.match(h.elements["profile-notice-copy"].textContent, /invented.*memory-only/);
  for (const id of ["logout", "logout-all", "password-panel"]) assert.equal(h.elements[id].hidden, false, id);
  const signedOut = await createHarness(async (path) => {
    assert.equal(path, "/api/v1/auth/status");
    return jsonResponse({ authenticated: false, setup_required: true });
  });
  assert.equal(signedOut.elements["logout"].hidden, true);
  assert.equal(signedOut.elements["dashboard-content"].hidden, true);
}
await testBrowserAuthFixtureKeepsVisibleRealAuthControls();

async function testUnavailableAuthIsVisibleAndRetryable() {
  let available = false;
  const { elements } = await createHarness(async (path) => {
    if (path !== "/api/v1/auth/status") throw new Error(`Unexpected request: ${path}`);
    if (!available) throw new Error("service unavailable");
    return jsonResponse({ authenticated: false, setup_required: true });
  });

  assert.equal(elements["auth-panel"].hidden, false);
  assert.equal(elements["auth-form"].hidden, true);
  assert.equal(elements["auth-retry"].hidden, false);
  assert.match(elements["auth-error"].textContent, /could not be reached/);
  assert.equal(elements["dashboard-content"].hidden, true);
  available = true;
  await elements["auth-retry"].listeners.get("click")();
  assert.equal(elements["auth-form"].hidden, false);
  assert.equal(elements["auth-retry"].hidden, true);
  assert.match(elements["auth-title"].textContent, /Set up/);
}

async function testExpiredSessionReturnsToLogin() {
  let expired = false;
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") {
      return jsonResponse(expired ? { authenticated: false, setup_required: false } : { authenticated: true });
    }
    if (expired) return jsonResponse({ error: "unauthorized" }, 401);
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  expired = true;
  await context.refreshSnapshot();
  assert.equal(elements["dashboard-content"].hidden, true);
  assert.equal(elements["auth-panel"].hidden, false);
  assert.equal(elements["auth-form"].hidden, false);
  assert.match(elements["auth-error"].textContent, /session expired/i);
}

function snapshotResponse(path, kernel = "retired-session-kernel") {
  if (path === "/api/v1/system") return jsonResponse({ ...systemFixture(), kernel });
  if (path === "/api/v1/storage") return jsonResponse(storageFixture());
  if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
  if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
  throw new Error(`Unexpected snapshot request: ${path}`);
}

const settleUI = () => new Promise((resolve) => setImmediate(resolve));

async function testSnapshotLateSuccessCannotSurviveAuthBoundary() {
  for (const boundary of ["logout", "logout-all", "password", "unavailable", "unauthenticated"]) {
    let ended = false;
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    const { context, elements, requests } = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !ended, setup_required: false });
      if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
      if (path === "/api/v1/auth/logout" || path === "/api/v1/auth/logout-all") { ended = true; return jsonResponse(path.endsWith("logout-all") ? { all_panel_sessions_revoked: true } : { logged_out: true }); }
      if (path === "/api/v1/auth/password") {
        ended = true;
        return jsonResponse({ password_changed: true, reauthentication_required: true, all_panel_sessions_revoked: true });
      }
      return pending.then(() => snapshotResponse(path));
    });
    if (boundary === "logout") await elements.logout.listeners.get("click")();
    else if (boundary === "logout-all") await elements["logout-all"].listeners.get("click")();
    else if (boundary === "password") {
      elements["password-current"].value = "old public test passphrase";
      elements["password-new"].value = "new public test passphrase";
      elements["password-confirm"].value = elements["password-new"].value;
      await elements["password-form"].listeners.get("submit")({ preventDefault() {} });
    } else if (boundary === "unauthenticated") {
      ended = true;
      await context.updateAuthView({ refresh: false });
    } else context.showAuthUnavailable();
    assert.equal(elements["dashboard-content"].hidden, true, "authentication boundary itself did not hide the dashboard");
    if (boundary === "logout") assert.equal(ended, true, "logout endpoint was not reached");
    const connection = elements["build-label"].textContent;
    const message = elements["snapshot-status"].textContent;
    release();
    await settleUI();
    assert.equal(elements["kernel-value"].textContent, "Unavailable", "late snapshot repopulated retired session values");
    assert.equal(elements["build-label"].textContent, connection, "late snapshot overwrote authentication state");
    assert.equal(elements["snapshot-status"].textContent, message);
    assert.equal(elements["dashboard-content"].hidden, true);
    const reads = requests.filter(({ path }) => ["system", "storage", "arrays", "mounts"].some((name) => path === `/api/v1/${name}`));
    assert.equal(reads.length, 4);
    assert.ok(reads.every(({ options }) => options.signal?.aborted), "retired reads were not canceled together");
  }
}

async function testSnapshotLateErrorsDoNotChangeUnavailableAuth() {
  for (const outcome of ["unauthorized", "transport-error", "body-error"]) {
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    const { context, elements, requests } = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
      await pending;
      if (outcome === "unauthorized") return jsonResponse({}, 401);
      if (outcome === "transport-error") return new Error("late transport failure");
      return { ok: true, status: 200, json: async () => { throw new Error("late malformed body"); },
        body: new ReadableStream({ start(controller) { controller.error(new Error("late malformed body")); } }) };
    });
    context.showAuthUnavailable();
    const message = elements["auth-error"].textContent;
    const requestCount = requests.length;
    release();
    await settleUI();
    assert.equal(elements["dashboard-content"].hidden, true);
    assert.equal(elements["auth-error"].textContent, message);
    assert.equal(elements["build-label"].textContent, "API unavailable");
    assert.equal(requests.length, requestCount, "retired response started another auth-status request");
  }
}

async function testSnapshotLateAuthBodyCannotReplaceNewSession() {
  let phase = "initial";
  let releaseAuth, releaseCurrent;
  const authBody = new Promise((resolve) => { releaseAuth = resolve; });
  const currentRead = new Promise((resolve) => { releaseCurrent = resolve; });
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return phase === "expired" ?
      deferredJSONResponse(authBody) : jsonResponse({ authenticated: true });
    if (phase === "expired") return jsonResponse({}, 401);
    if (phase === "current") await currentRead;
    return snapshotResponse(path, "current-session-kernel");
  });
  phase = "expired";
  const retired = context.refreshSnapshot();
  await settleUI();
  context.showAuthUnavailable();
  phase = "current";
  await context.updateAuthView({ refresh: false });
  const fresh = context.refreshSnapshot();
  await settleUI();
  releaseAuth({ authenticated: false, setup_required: false });
  await retired;
  await settleUI();
  assert.equal(elements["dashboard-content"].hidden, false);
  assert.equal(elements["auth-panel"].hidden, true);
  assert.equal(elements.refresh.disabled, true, "retired finalizer unlocked a current refresh");
  assert.equal(elements.refresh.attributes.get("aria-busy"), "true");
  assert.equal(elements["refresh-label"].textContent, "Refreshing…");
  releaseCurrent();
  await fresh;
  assert.equal(elements["kernel-value"].textContent, "Linux current-session-kernel");
  assert.equal(elements.refresh.disabled, false);
}

async function testSnapshotReadIsSingleFlight() {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const { context, elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    return pending.then(() => snapshotResponse(path));
  });
  const duplicate = context.refreshSnapshot();
  await settleUI();
  const countWhilePending = requests.filter(({ path }) => path !== "/api/v1/auth/status").length;
  release();
  await duplicate;
  await settleUI();
  assert.equal(countWhilePending, 4, "concurrent refresh started duplicate diagnostic reads");
  assert.equal(elements.refresh.disabled, false);
  assert.equal(elements["refresh-label"].textContent, "Refresh snapshot");
  const reads = requests.filter(({ path }) => path !== "/api/v1/auth/status");
  assert.ok(reads[0].options.signal);
  assert.ok(reads.every(({ options }) => options.signal === reads[0].options.signal));
}

async function testSnapshotDeadlineIncludesBodyAndDoesNotRetry() {
  let releaseBody;
  const body = new Promise((resolve) => { releaseBody = resolve; });
  const timers = new Map();
  let nextTimer = 0;
  const { elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return deferredJSONResponse(body);
    return snapshotResponse(path);
  }, {
    setTimeout: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout: (id) => timers.delete(id),
  });
  assert.equal(timers.size, 1, "snapshot has no finite client deadline");
  const deadline = [...timers.values()][0];
  assert.equal(deadline.delay, 10000);
  deadline.callback();
  await settleUI();
  assert.equal(elements["kernel-value"].textContent, "Unavailable");
  assert.match(elements["snapshot-status"].textContent, /system observation unavailable/);
  assert.equal(elements.refresh.disabled, false);
  assert.equal(timers.size, 0);
  const before = elements["snapshot-status"].textContent;
  releaseBody({ ...systemFixture(), kernel: "late-body-kernel" });
  await settleUI();
  assert.equal(elements["kernel-value"].textContent, "Unavailable");
  assert.equal(elements["snapshot-status"].textContent, before);
  assert.equal(requests.filter(({ path }) => path !== "/api/v1/auth/status").length, 4);
}

async function testStorageFailureKeepsOnlyCurrentSystemObservation() {
  let storageAvailable = true;
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") {
      return storageAvailable ? jsonResponse(storageFixture([blockFixture()])) : jsonResponse({ error: "unavailable" }, 503);
    }
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  storageAvailable = false;
  await context.refreshSnapshot();
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.54");
  assert.equal(elements["device-count"].textContent, "Storage unavailable");
  assert.match(elements["device-list"].children[0].textContent, /no current device values/i);
  assert.equal(elements["service-status-dot"].className.includes("is-degraded"), true);
  assert.match(elements["snapshot-status"].textContent, /system.*current.*storage.*unavailable/i);
  assert.match(elements["error-banner"].textContent, /no previous values are shown for the unavailable section/i);
}

async function testSystemFailureKeepsOnlyCurrentStorageObservation() {
  let systemAvailable = true;
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return systemAvailable ? jsonResponse(systemFixture()) : jsonResponse({ error: "unavailable" }, 503);
    if (path === "/api/v1/storage") return jsonResponse(storageFixture([blockFixture()]));
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  systemAvailable = false;
  await context.refreshSnapshot();
  assert.equal(elements["kernel-value"].textContent, "Unavailable");
  assert.equal(elements["observed-at"].textContent, "No current system observation");
  assert.equal(elements["profile-notice-title"].textContent, "System profile unavailable.");
  assert.equal(elements["device-count"].textContent, "1 device");
  assert.equal(elements["device-list"].children[0].children[0].children[1].children[0].textContent, "sda");
  assert.equal(elements["service-status-dot"].className.includes("is-degraded"), true);
  assert.match(elements["snapshot-status"].textContent, /storage.*current.*system.*unavailable/i);
}

async function testAllDiagnosticFailuresClearValues() {
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system" || path === "/api/v1/storage" || path === "/api/v1/arrays" || path === "/api/v1/mounts") return jsonResponse({ error: "unavailable" }, 503);
    throw new Error(`Unexpected request: ${path}`);
  });

  assert.equal(elements["kernel-value"].textContent, "Unavailable");
  assert.match(elements["snapshot-status"].textContent, /system, storage, RAID, and mount.*unavailable.*cleared/i);
  assert.equal(elements["error-banner"].hidden, false);
  assert.equal(elements["service-status-dot"].className.includes("is-unavailable"), true);
  assert.match(elements["device-list"].children[0].textContent, /no current device values/i);
}

async function testMountFailureClearsOnlyMountObservation() {
  let mountsAvailable = true;
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture([blockFixture()]));
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return mountsAvailable ? jsonResponse(mountsFixture()) : jsonResponse({ error: "unavailable" }, 503);
    throw new Error(`Unexpected request: ${path}`);
  });

  mountsAvailable = false;
  await context.refreshSnapshot();
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.54");
  assert.equal(elements["device-count"].textContent, "1 device");
  assert.equal(elements["array-count"].textContent, "2 arrays");
  assert.equal(elements["mount-count"].textContent, "Mounts unavailable");
  assert.match(elements["mount-list"].children[0].textContent, /no current mount values/i);
  assert.equal(elements["service-status-dot"].className.includes("is-degraded"), true);
  assert.match(elements["snapshot-status"].textContent, /system, storage, RAID.*current.*mount.*unavailable/i);
}

async function testGPTObservationRunsOnlyOnExplicitClickAndUsesRedactedCSRFRequest() {
  const summary = {
    schema_version: 1, status: "complete", scope: "manual-gpt-metadata-read-only",
    eligible_candidate_count: 2, gpt_disk_count: 2, partition_count: 4,
    unsupported_or_non_gpt_count: 0, gpt_coverage: "all-candidates-gpt",
    ambiguous_disk_guid_count: 0, ambiguous_partuuid_count: 0, identity_evidence_incomplete: false,
    content_read: false, mount_performed: false, assembly_performed: false, import_performed: false,
    mutations_performed: false, limitations: ["one", "two", "three", "four", "five"],
  };
  const { elements, requests } = await createHarness(async (path, options) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/storage/gpt-observation") return jsonResponse(summary);
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path} ${JSON.stringify(options)}`);
  });

  assert.equal(elements["gpt-observation-status"].textContent.includes("Complete observation"), false);
  assert.equal(requests.some(({ path }) => path === "/api/v1/storage/gpt-observation"), false,
    "page load and the ordinary refresh must not probe GPT metadata");
  await elements["gpt-observe"].listeners.get("click")();
  const request = requests.find(({ path }) => path === "/api/v1/storage/gpt-observation");
  assert.ok(request);
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.headers["X-PhantoWD-CSRF"], "x".repeat(43));
  assert.equal(request.options.headers["Content-Type"], undefined);
  assert.equal(request.options.body, undefined);
  assert.equal(request.options.credentials, "same-origin");
  assert.match(elements["gpt-observation-status"].textContent, /2 eligible candidates; 2 GPT disks; 4 GPT partitions/);
  assert.equal(elements["gpt-observation-status"].textContent.includes("12345678-1234"), false);
  assert.equal(elements["gpt-observe"].disabled, false);

  Object.assign(summary, {
    eligible_candidate_count: 6, gpt_disk_count: 6, partition_count: 1536,
    ambiguous_partuuid_count: 1536, unsupported_or_non_gpt_count: 0,
  });
  await elements["gpt-observe"].listeners.get("click")();
  assert.match(elements["gpt-observation-status"].textContent, /6 eligible candidates; 6 GPT disks; 1536 GPT partitions/,
    "the UI must accept the bounded six-device QEMU fixture without weakening validation");
}

function policyFixture() {
  return { schema_version: 1, scope: "desired-policy-only", persisted: false, applied: false, runtime_validated: false, activation_available: false,
    requirements: ["runtime_volume_identity", "path_and_mount_containment", "unix_accounts_and_effective_access", "durable_configuration", "service_activation_lifecycle", "cross_protocol_access_review"],
    samba: { samba_share_sections: "[Books]\npath = /example/<script>" }, nfs: { exports_table: "/example client(ro)" } };
}

function fillPolicy(elements) {
  const values = { uuid: "11111111-2222-3333-4444-555555555555", name: "Books", path: "books", user: "reader", "smb-access": "ro", "nfs-enabled": "on", "export-id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", network: "192.0.2.10/32", "nfs-access": "ro", squash: "all", uid: "65534", gid: "65534", security: "sys" };
  for (const [id, value] of Object.entries(values)) elements[`policy-${id}`].value = value;
}

async function policyHarness(previewResponse = () => jsonResponse(policyFixture()), sessionResponse = () => jsonResponse({ csrf_token: "fixture-only" }), savedResponse = () => jsonResponse(savedFixture())) {
  return createHarness(async (path, options) => {
    if (path === "/api/v1/shares/configuration") return savedResponse(options);
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return sessionResponse();
    if (path === "/api/v1/file-services/preview") return previewResponse(options);
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request ${path}`);
  });
}

async function testPolicyBuilderAndSafePreview() {
  const overlapPreview = policyFixture();
  overlapPreview.requirements.push("cross_protocol_path_overlap");
  const { context, elements, requests } = await policyHarness(() => jsonResponse(overlapPreview));
  fillPolicy(elements);
  context.syncPolicyNFS();
  assert.equal(elements["policy-nfs-fields"].disabled, false);
  await context.submitPolicyProposal({ preventDefault() {} });
  const request = requests.find(({ path }) => path.endsWith("/preview"));
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.headers["X-PhantoWD-CSRF"], "fixture-only");
  assert.equal(request.options.credentials, "same-origin");
  const proposal = JSON.parse(request.options.body);
  assert.equal(proposal.shares.volumes[0].filesystem_uuid, elements["policy-uuid"].value);
  assert.equal(proposal.shares.shares[0].grants[0].access, "ro");
  assert.equal(proposal.nfs.volume_revision, proposal.shares.revision);
  assert.equal(proposal.nfs.exports[0].clients[0].anonymous_uid, 65534);
  assert.equal(proposal.nfs.exports[0].clients[0].squash, "all");
  assert.equal(elements["policy-result"].hidden, false);
  assert.match(elements["policy-status"].textContent, /Not saved or applied/);
  assert.ok(elements["policy-requirements"].children.some((item) => /configured SMB\/NFS paths overlap/i.test(item.textContent)),
    "the preview should explain configured cross-protocol path overlap");
  assert.equal(elements["policy-samba"].textContent, policyFixture().samba.samba_share_sections);
  assert.equal(elements["policy-samba"].children.length, 0);
  elements["policy-form"].listeners.get("input")();
  assert.equal(elements["policy-result"].hidden, true);
  assert.equal(elements["policy-samba"].textContent, "");
  elements["policy-nfs-enabled"].value = "off";
  elements["policy-uid"].value = "invalid ignored when disabled";
  context.syncPolicyNFS();
  assert.equal(elements["policy-nfs-fields"].disabled, true);
  assert.equal(context.buildPolicyProposal().nfs.exports.length, 0);
  context.clearPolicyDraft();
  assert.equal(elements["policy-uuid"].value, "");
  assert.equal(elements["policy-nfs-enabled"].value, "off");
  assert.equal(elements["policy-submit"].disabled, false);
}

async function testPolicyFailuresAndStaleResponses() {
  for (const response of [jsonResponse({}, 422), jsonResponse({}, 403), jsonResponse({}, 503), jsonResponse({ ...policyFixture(), applied: true }), jsonResponse({ ...policyFixture(), applied: undefined }), jsonResponse({ ...policyFixture(), requirements: ["__proto__"] }), jsonResponse({ ...policyFixture(), requirements: [] })]) {
    const { context, elements } = await policyHarness(() => response);
    fillPolicy(elements);
    await context.submitPolicyProposal({ preventDefault() {} });
    assert.equal(elements["policy-result"].hidden, true);
    assert.equal(elements["policy-error"].hidden, false);
    assert.equal(elements["policy-submit"].disabled, false);
  }
  const { context, elements, requests } = await policyHarness();
  fillPolicy(elements);
  elements["policy-uid"].value = "1e3";
  await context.submitPolicyProposal({ preventDefault() {} });
  assert.match(elements["policy-error"].textContent, /whole numbers/);
  assert.equal(requests.some(({ path }) => path.endsWith("/session")), false);
  for (const sessionReply of [jsonResponse({}, 503), jsonResponse({}), jsonResponse({ csrf_token: "" })]) {
    const harness = await policyHarness(undefined, () => sessionReply);
    fillPolicy(harness.elements);
    await harness.context.submitPolicyProposal({ preventDefault() {} });
    assert.equal(harness.requests.some(({ path }) => path.endsWith("/preview")), false);
    assert.equal(harness.elements["policy-error"].hidden, false);
  }
  const timedOut = await policyHarness(() => { const error = new Error("aborted"); error.name = "AbortError"; throw error; });
  fillPolicy(timedOut.elements);
  await timedOut.context.submitPolicyProposal({ preventDefault() {} });
  assert.match(timedOut.elements["policy-error"].textContent, /timed out/);
  timedOut.context.showAuthUnavailable();
  assert.equal(timedOut.elements["policy-user"].value, "");

  for (const duringSession of [false, true]) {
    let release;
    const pending = new Promise((resolve) => { release = resolve; });
    const harness = await policyHarness(duringSession ? undefined : () => pending, duringSession ? () => pending : undefined);
    fillPolicy(harness.elements);
    const operation = harness.context.submitPolicyProposal({ preventDefault() {} });
    await new Promise((resolve) => setImmediate(resolve));
    await harness.context.submitPolicyProposal({ preventDefault() {} }); // duplicate ignored
    harness.context.clearPolicyDraft(); // also used at logout/auth loss
    release(duringSession ? jsonResponse({ csrf_token: "fixture-only" }) : jsonResponse(policyFixture()));
    await operation;
    assert.equal(harness.elements["policy-result"].hidden, true);
    assert.equal(harness.elements["policy-samba"].textContent, "");
    assert.equal(harness.elements["policy-uuid"].value, "");
    assert.equal(harness.requests.filter(({ path }) => path.endsWith("/preview")).length, duringSession ? 0 : 1);
  }
}

function savedFixture() {
  return {
    schema_version: 1, scope: "stored-desired-share-policy-only", initialized: true,
    runtime_validated: false, activation_available: false,
    configuration: {
      format: "phantowd-share-config", schema_version: 1, revision: 4,
      volumes: [{ id: "media", filesystem_uuid: "11111111-2222-3333-4444-555555555555" }],
      users: [{ id: "reader", name: "reader" }],
      shares: [{ id: "books", name: "Books", volume_id: "media", relative_path: "books", grants: [{ user_id: "reader", access: "ro" }] }],
    },
  };
}

async function testSavedPolicyStatesAndSafeRendering() {
  let response = jsonResponse(savedFixture());
  const { context, elements, requests } = await policyHarness(undefined, undefined, () => response);
  assert.equal(requests.some(({ path }) => path.endsWith("/configuration")), false, "loading must be explicit");
  await elements["saved-load"].listeners.get("click")();
  const request = requests.find(({ path }) => path.endsWith("/configuration"));
  assert.equal(request.options.method, "GET");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.body, undefined);
  assert.equal(elements["saved-result"].hidden, false);
  assert.match(elements["saved-summary"].textContent, /Revision 4/);
  assert.match(elements["saved-status"].textContent, /Runtime access has not been verified/);
  const row = elements["saved-shares"].children[0];
  assert.equal(row.children[0].textContent, "Books");
  assert.equal(row.children[1].textContent, "media / books");
  assert.match(row.children[3].children[1].textContent, /reader: read only/);

  // Even a hostile, structurally valid reply is rendered as text, never markup.
  const hostile = savedFixture();
  hostile.configuration.shares[0].name = "<img src=x onerror=alert(1)>";
  hostile.configuration.shares[0].relative_path = "<script>payload</script>";
  response = jsonResponse(hostile);
  await context.loadSavedPolicy();
  assert.equal(elements["saved-shares"].children[0].children[0].textContent, hostile.configuration.shares[0].name);
  assert.equal(elements["saved-shares"].children[0].children[0].children.length, 0);

  const empty = savedFixture();
  empty.configuration.shares = [];
  response = jsonResponse(empty);
  await context.loadSavedPolicy();
  assert.equal(elements["saved-result"].hidden, false);
  assert.equal(elements["saved-shares"].children.length, 0);
  assert.match(elements["saved-status"].textContent, /no shares are defined/);

  for (const [reply, expected] of [
    [jsonResponse({ ...savedFixture(), initialized: false, configuration: null }), /no share policy has been initialized/],
    [jsonResponse({ error: "share_configuration_not_configured" }, 503), /storage is not connected/],
    [jsonResponse({ error: "share_configuration_unavailable" }, 503), /unavailable or busy/],
    [jsonResponse({}, 403), /unavailable or busy/],
    [Object.assign(new Error("private backend details"), { name: "AbortError" }), /timed out/],
    [new Error("private backend details"), /could not be verified/],
  ]) {
    response = jsonResponse(savedFixture());
    await context.loadSavedPolicy();
    response = reply;
    await context.loadSavedPolicy();
    assert.equal(elements["saved-result"].hidden, true);
    assert.equal(elements["saved-shares"].children.length, 0);
    assert.equal(elements["saved-summary"].textContent, "");
    assert.match(elements["saved-status"].textContent, expected);
    assert.doesNotMatch(elements["saved-status"].textContent, /private/);
    assert.equal(elements["saved-load"].disabled, false);
  }
}

async function testSavedPolicyMalformedReplies() {
  for (const mutate of [
    (r) => { r.schema_version = 2; },
    (r) => { r.scope = "active-shares"; },
    (r) => { delete r.runtime_validated; },
    (r) => { r.activation_available = true; },
    (r) => { r.initialized = false; },
    (r) => { r.configuration = null; },
    (r) => { r.configuration.format = "unknown"; },
    (r) => { r.configuration.revision = Number.MAX_SAFE_INTEGER + 1; },
    (r) => { r.configuration.volumes.push(r.configuration.volumes[0]); },
    (r) => { r.configuration.volumes = Array(17).fill(r.configuration.volumes[0]); },
    (r) => { r.configuration.volumes[0].filesystem_uuid = "not-a-uuid"; },
    (r) => { r.configuration.users.push(r.configuration.users[0]); },
    (r) => { r.configuration.shares[0].volume_id = "missing"; },
    (r) => { r.configuration.shares[0].grants[0].user_id = "missing"; },
    (r) => { r.configuration.shares[0].grants[0].access = "admin"; },
    (r) => { r.configuration.shares[0].grants.push(r.configuration.shares[0].grants[0]); },
    (r) => { r.configuration.shares[0].relative_path = "x".repeat(1025); },
  ]) {
    const reply = savedFixture(); mutate(reply);
    const { context, elements } = await policyHarness(undefined, undefined, () => jsonResponse(reply));
    await context.loadSavedPolicy();
    assert.equal(elements["saved-result"].hidden, true);
    assert.match(elements["saved-status"].textContent, /could not be verified/);
    assert.equal(elements["saved-shares"].children.length, 0);
  }
}

async function testSavedPolicyLateRepliesAndAuthLoss() {
  for (const delayedBody of [false, true]) {
    for (const reset of ["clear", "auth-loss", "logout"]) {
      let release;
      const pending = new Promise((resolve) => { release = resolve; });
      const harness = await policyHarness(undefined, () => jsonResponse({}, 503), () =>
        delayedBody ? deferredJSONResponse(pending) : pending);
      const { context, elements, requests } = harness;
      const operation = context.loadSavedPolicy();
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(elements["saved-load"].disabled, true);
      await context.loadSavedPolicy(); // duplicate ignored
      if (reset === "clear") context.clearSavedPolicy();
      if (reset === "auth-loss") context.showAuthUnavailable();
      if (reset === "logout") await elements.logout.listeners.get("click")();
      release(delayedBody ? savedFixture() : jsonResponse(savedFixture()));
      await operation;
      assert.equal(requests.filter(({ path }) => path.endsWith("/configuration")).length, 1);
      assert.equal(requests.find(({ path }) => path.endsWith("/configuration")).options.signal.aborted, true);
      assert.equal(elements["saved-result"].hidden, true);
      assert.equal(elements["saved-shares"].children.length, 0);
      assert.equal(elements["saved-load"].disabled, false);
    }
  }
  for (const statusFails of [false, true]) {
    let expired = false;
    const { context, elements } = await createHarness(async (path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !expired, setup_required: false }, expired && statusFails ? 503 : 200);
      if (path === "/api/v1/shares/configuration") { expired = true; return jsonResponse({}, 401); }
      if (path === "/api/v1/system") return jsonResponse(systemFixture());
      if (path === "/api/v1/storage") return jsonResponse(storageFixture());
      if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
      if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
      throw new Error(`Unexpected request ${path}`);
    });
    await context.loadSavedPolicy();
    assert.equal(elements["dashboard-content"].hidden, true);
    assert.equal(elements["auth-panel"].hidden, false);
    assert.equal(elements["saved-result"].hidden, true);
  }
}

function serviceReply(configuration) {
  return { schema_version: 1, scope: "development-stored-file-service-policy-only", initialized: configuration !== null,
    configuration, applied: false, runtime_validated: false, activation_available: false };
}

function serviceSaved(revision) {
  return { schema_version: 1, scope: "development-stored-file-service-policy-only", revision, saved: true,
    applied: false, runtime_validated: false, activation_available: false };
}

async function serviceHarness(stateResponse, previewResponse = () => jsonResponse(policyFixture()), sessionResponse = () => jsonResponse({ csrf_token: "fixture-only" }), backupResponse = () => { throw new Error("unexpected backup request"); }, authResponse = () => jsonResponse({ authenticated: true })) {
  return createHarness(async (path, options) => {
    if (path === "/api/v1/file-services/configuration") return stateResponse(options);
    if (path === "/api/v1/auth/status") return authResponse(options);
    if (path === "/api/v1/auth/session") return sessionResponse();
    if (path === "/api/v1/file-services/preview") return previewResponse(options);
    if (path === "/api/v1/file-services/backup" || path === "/api/v1/file-services/restore-preview") return backupResponse(path, options);
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request ${path}`);
  });
}

async function testServiceAddAndPreserve() {
  let saved = null;
  const { context, elements, requests } = await serviceHarness((options) => {
    if (options.method === "PUT") { saved = JSON.parse(options.body); return jsonResponse(serviceSaved(saved.revision)); }
    return jsonResponse(serviceReply(saved));
  });
  await context.saveServiceChange();
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
  await context.loadServicePolicy();
  assert.match(elements["service-summary"].textContent, /no configuration initialized/);
  fillPolicy(elements);
  await context.prepareServiceAddition();
  assert.equal(elements["service-save"].disabled, false);
  assert.equal(elements["service-review"].hidden, false);
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false, "preview must not save");
  assert.match(elements["service-samba"].textContent, /<script>/, "render as text only");
  await context.saveServiceChange();
  assert.equal(saved.revision, 1);
  assert.equal(saved.nfs.volume_revision, 1);
  assert.equal(saved.shares.volumes.length, 1);
  const previous = structuredClone(saved);
  assert.match(elements["service-status"].textContent, /confirmed saved.*No services were activated/);
  elements["policy-name"].value = "Comics"; elements["policy-path"].value = "comics";
  elements["policy-export-id"].value = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
  context.invalidatePolicyPreview();
  await context.prepareServiceAddition(); await context.saveServiceChange();
  assert.equal(saved.revision, 2);
  assert.deepEqual(saved.shares.shares[0], previous.shares.shares[0]);
  assert.deepEqual(saved.nfs.exports[0], previous.nfs.exports[0]);
  assert.equal(saved.shares.volumes.length, 1, "reuse same UUID");
  assert.equal(saved.shares.users.length, 1, "reuse named account reference");
  assert.equal(saved.shares.shares.length, 2);
  assert.notEqual(saved.shares.shares[0].id, saved.shares.shares[1].id);
  await context.prepareServiceAddition();
  assert.match(elements["service-status"].textContent, /already exists/);
  assert.equal(elements["service-save"].disabled, true);
  assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 2);
  for (const { options } of requests.filter(({ options }) => options?.method === "PUT")) {
    assert.equal(options.headers["X-PhantoWD-CSRF"], "fixture-only");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.cache, "no-store");
  }
}

async function testServiceUncertainAndConflict() {
  for (const result of ["lost-but-saved", "lost-not-saved", "conflict", "invalid-success", "unavailable"]) {
    let saved = null;
    const { context, elements, requests } = await serviceHarness((options) => {
      if (options.method === "PUT") {
        if (result === "lost-but-saved") saved = JSON.parse(options.body);
        if (result === "conflict") return jsonResponse({}, 409);
        if (result === "unavailable") return jsonResponse({}, 503);
        if (result === "invalid-success") return jsonResponse({ saved: true });
        return new Error("private transport detail");
      }
      // Change object-key order; the full structure, not raw serialization, matters.
      return jsonResponse(serviceReply(saved === null ? null : Object.fromEntries(Object.entries(saved).reverse())));
    });
    fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceChange();
    assert.match(elements["service-status"].textContent, result === "conflict" ? /Revision conflict.*refused/ : /not confirmed.*may have committed/);
    assert.equal(elements["service-save"].disabled, true);
    assert.equal(elements["service-prepare"].disabled, true);
    await context.saveServiceChange(); await context.prepareServiceAddition();
    assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
    await context.loadServicePolicy();
    assert.match(elements["service-status"].textContent, result === "lost-but-saved" ? /complete attempted configuration.*confirmed saved/ : /differs.*not retried/);
    assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
    assert.equal(elements["service-prepare"].disabled, false);
  }
  // Same revision with different content is never confirmation.
  const { context, elements } = await serviceHarness(() => jsonResponse(serviceReply(null)));
  fillPolicy(elements);
  const proposal = context.buildPolicyProposal();
  const a = context.buildServiceAddition(null, proposal);
  const b = structuredClone(a); b.shares.shares[0].name = "Different";
  assert.equal(context.sameServiceDocument(a, b), false);
}

async function testServiceRefusalsAndInvalidation() {
  for (const reply of [jsonResponse({}, 503), jsonResponse(serviceReply({ revision: 1 })), new Error("private failure")]) {
    const { context, elements, requests } = await serviceHarness(() => reply);
    fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceChange();
    assert.equal(elements["service-current"].hidden, true);
    assert.equal(elements["service-save"].disabled, true);
    assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
    assert.doesNotMatch(elements["service-status"].textContent, /private failure/);
  }
  const { context, elements, requests } = await serviceHarness(() => jsonResponse(serviceReply(null)), () => jsonResponse({}, 422));
  fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceChange();
  assert.equal(elements["service-save"].disabled, true);
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
  for (const boundary of ["preview", "save-session", "save-reply", "load"]) {
    let release, delay = false;
    const pending = new Promise((resolve) => { release = resolve; });
    const h = await serviceHarness((options) => {
      if (boundary === "load" && delay) return pending;
      if (options.method === "PUT") return boundary === "save-reply" ? pending : jsonResponse(serviceSaved(1));
      return jsonResponse(serviceReply(null));
    }, () => boundary === "preview" ? pending : jsonResponse(policyFixture()),
    () => boundary === "save-session" && delay ? pending : jsonResponse({ csrf_token: "fixture-only" }));
    fillPolicy(h.elements); await h.context.loadServicePolicy();
    if (boundary !== "preview") await h.context.prepareServiceAddition();
    delay = true;
    const operation = boundary === "preview" ? h.context.prepareServiceAddition() : boundary === "load" ? h.context.loadServicePolicy() : h.context.saveServiceChange();
    await new Promise((resolve) => setImmediate(resolve));
    // Auth loss must cancel and prevent a late response from restoring sensitive data.
    h.context.showAuthUnavailable();
    release(jsonResponse(boundary === "preview" ? policyFixture() : boundary === "save-session" ? { csrf_token: "fixture-only" } : boundary === "load" ? serviceReply(null) : serviceSaved(1)));
    await operation;
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.elements["service-current"].hidden, true);
    assert.equal(h.elements["service-document"].textContent, "");
    assert.equal(h.elements["service-diff"].children.length, 0);
    assert.equal(h.elements["service-diff-summary"].textContent, "");
    assert.equal(h.elements["service-overlaps"].children.length, 0);
    assert.equal(h.elements["service-overlap-summary"].textContent, "");
    assert.equal(h.elements["service-save"].disabled, true);
    assert.equal(h.requests.filter(({ options }) => options?.method === "PUT").length, boundary === "save-reply" ? 1 : 0);
  }
}

async function testServiceFormEditsAndReconcileFailure() {
  for (const phase of ["preview", "save-session"]) {
    let release, delay = false;
    const pending = new Promise((resolve) => { release = resolve; });
    const { context, elements, requests } = await serviceHarness(() => jsonResponse(serviceReply(null)),
      () => phase === "preview" && delay ? pending : jsonResponse(policyFixture()),
      () => phase === "save-session" && delay ? pending : jsonResponse({ csrf_token: "fixture-only" }));
    fillPolicy(elements); await context.loadServicePolicy();
    if (phase === "save-session") await context.prepareServiceAddition();
    delay = true;
    const operation = phase === "preview" ? context.prepareServiceAddition() : context.saveServiceChange();
    await new Promise((resolve) => setImmediate(resolve));
    elements["policy-name"].value = "Edited during request";
    context.invalidatePolicyPreview();
    release(jsonResponse(phase === "preview" ? policyFixture() : { csrf_token: "fixture-only" }));
    await operation;
    assert.equal(elements["service-save"].disabled, true);
    assert.equal(elements["service-review"].hidden, true);
    assert.match(elements["service-status"].textContent, /Form changed/);
    assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
  }
  let failed = false;
  const { context, elements, requests } = await serviceHarness((options) => {
    if (options.method === "PUT") { failed = true; return new Error("lost response"); }
    return failed ? jsonResponse({}, 503) : jsonResponse(serviceReply(null));
  });
  fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceChange();
  await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceChange();
  assert.equal(elements["service-save"].disabled, true);
  assert.equal(elements["service-prepare"].disabled, true);
  assert.equal(elements["service-current"].hidden, true);
  assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
}

await testServiceAddAndPreserve();
await testServiceUncertainAndConflict();
await testServiceRefusalsAndInvalidation();
await testServiceFormEditsAndReconcileFailure();
await testServiceEditingContracts();
await testServiceEditorInteraction();
await testServiceUserReferenceContracts();
await testServiceUserReferenceInteraction();
await testServiceUserReferenceUncertainSave();
await testSavedPolicyStatesAndSafeRendering();
await testSavedPolicyMalformedReplies();
await testSavedPolicyLateRepliesAndAuthLoss();
await testPolicyBuilderAndSafePreview();
await testPolicyFailuresAndStaleResponses();
await testReadOnlySnapshotAndSafeRendering();
await testSnapshotLoadAgeUsesOnlyBrowserElapsedTime();
await testSnapshotLoadAgeRefusesInvalidOrRegressingClock();
await testSnapshotAgeLifecycleAndPartialResults();
await testUnavailableAuthIsVisibleAndRetryable();
await testExpiredSessionReturnsToLogin();
await testAuthFocusMovesOnlyWhenItsControlIsHidden();
await testAuthFocusAfterPasswordChangeOrUncertainty();
await testAuthFocusDoesNotFollowRetiredOrUnrelatedReads();
await testSnapshotLateSuccessCannotSurviveAuthBoundary();
await testSnapshotLateErrorsDoNotChangeUnavailableAuth();
await testSnapshotLateAuthBodyCannotReplaceNewSession();
await testSnapshotReadIsSingleFlight();
await testSnapshotDeadlineIncludesBodyAndDoesNotRetry();
await testStorageFailureKeepsOnlyCurrentSystemObservation();
await testSystemFailureKeepsOnlyCurrentStorageObservation();
await testAllDiagnosticFailuresClearValues();
await testMountFailureClearsOnlyMountObservation();
await testMalformedStorageDoesNotBecomeEmptyOrClearOtherDomains();
await testStorageCountIsNotAnEmptyInventory();
await testStorageEnvelopeCannotClaimCurrentData();
await testMalformedStorageRowClearsOnlyStorage();
await testStorageDisplayEnvelopeBoundsAndInvalidReport();
await testGPTObservationRunsOnlyOnExplicitClickAndUsesRedactedCSRFRequest();

async function testMalformedStorageDoesNotBecomeEmptyOrClearOtherDomains() {
  let storage = storageFixture([{ name: "sda", kind: "block", major: 8, minor: 0,
    size_bytes: 2 ** 40, read_only: false, removable: false,
    serial_status: "present", wwn_status: "present" }]);
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/storage") return jsonResponse(storage);
    return snapshotResponse(path, "current-kernel");
  });
  await settleUI();
  assert.equal(h.elements["device-count"].textContent, "1 device");
  storage = {};
  const before = h.requests.length;
  await h.context.refreshSnapshot();
  assert.equal(h.elements["device-count"].textContent, "Storage unavailable",
    "HTTP success without an inventory must not claim zero kernel devices");
  assert.match(h.elements["device-list"].children[0].textContent, /no current device values/i);
  assert.equal(h.elements["kernel-value"].textContent, "Linux current-kernel");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
  assert.equal(h.elements["mount-count"].textContent, "2 mounts");
  assert.match(h.elements["snapshot-status"].textContent, /system, RAID, mount.*current.*storage.*unavailable/i);
  assert.equal(h.requests.length - before, 4, "invalid data must not add or retry requests");
}

async function testStorageCountIsNotAnEmptyInventory() {
  let storage = storageFixture();
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/storage" ? jsonResponse(storage) : snapshotResponse(path));
  await settleUI();
  assert.equal(h.elements["device-count"].textContent, "0 devices");
  storage = { ...storageFixture(), device_count: 1 };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["device-count"].textContent, "Storage unavailable",
    "A missing declared row must not become a complete empty inventory");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
}

async function testStorageEnvelopeCannotClaimCurrentData() {
  const storage = { ...storageFixture(), schema_version: 1 };
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/storage" ? jsonResponse(storage) : snapshotResponse(path));
  await settleUI();
  assert.equal(h.elements["device-count"].textContent, "Storage unavailable",
    "Unsupported storage schema must not claim an empty current inventory");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
}

async function testMalformedStorageRowClearsOnlyStorage() {
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/storage" ? jsonResponse(storageFixture([null])) : snapshotResponse(path));
  await settleUI();
  assert.equal(h.elements["device-count"].textContent, "Storage unavailable");
  assert.equal(h.elements["kernel-value"].textContent, "Linux retired-session-kernel",
    "A malformed row must not clear independently valid system data");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
  assert.equal(h.elements["mount-count"].textContent, "2 mounts");
}

async function testStorageDisplayEnvelopeBoundsAndInvalidReport() {
  const empty = storageFixture();
  const invalid = [null, {}, [], true, "PRIVATE-SENTINEL",
    { ...empty, observations: null }, { ...empty, observations: "PRIVATE-SENTINEL" },
    { ...empty, device_count: "0" }, { ...empty, device_count: -1 }, { ...empty, device_count: 1 },
    { ...empty, schema_version: 1 }, { ...empty, schema_version: "2" },
    { ...empty, scope: "PRIVATE-SENTINEL" }, { ...empty, inventory_read_only: false },
    { ...empty, block_devices_opened: true }, { ...empty, content_read: true },
    { ...empty, mutations_performed: true }, { ...empty, stable_identity_available: true },
    storageFixture([null]), storageFixture([[]]), storageFixture(["PRIVATE-SENTINEL"]),
    storageFixture([blockFixture({ kind: "disk" })]),
    storageFixture([blockFixture({ read_only: "false" })]),
    storageFixture([blockFixture({ removable: 0 })]),
    storageFixture([blockFixture({ serial_status: "PRIVATE-SENTINEL" })]),
    storageFixture([blockFixture({ wwn_status: null })]),
    storageFixture(Array.from({ length: 33 }, () => blockFixture())),
  ];
  let storage = empty, round = 0;
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/storage" ? jsonResponse(storage) : snapshotResponse(path, `fresh-${round}`));
  await settleUI();
  assert.equal(h.elements["device-count"].textContent, "0 devices", "A validated complete empty inventory stays distinguishable");
  for (const value of invalid) {
    storage = value;
    round++;
    const before = h.requests.length;
    await h.context.refreshSnapshot();
    assert.equal(h.elements["device-count"].textContent, "Storage unavailable", `invalid storage case ${round}`);
    assert.equal(h.elements["kernel-value"].textContent, `Linux fresh-${round}`, "Valid domains must be refreshed, not reused");
    assert.equal(h.elements["array-count"].textContent, "2 arrays");
    assert.equal(h.elements["mount-count"].textContent, "2 mounts");
    assert.equal(h.requests.length - before, 4, "No retry/auth/probe is added for invalid data");
    assert.ok(!h.elements["snapshot-status"].textContent.includes("PRIVATE-SENTINEL"));
    const report = JSON.parse(new Script("supportSnapshot.serialize(Date.now())").runInContext(h.context));
    assert.equal(report.observations.storage.status, value === null ? "unavailable" : "invalid");
    assert.ok(!JSON.stringify(report).includes("PRIVATE-SENTINEL"));
  }
  storage = storageFixture(Array.from({ length: 32 }, (_, i) => blockFixture({ name: `disk-${i}` })));
  await h.context.refreshSnapshot();
  assert.equal(h.elements["device-count"].textContent, "32 devices");
  assert.equal(h.elements["device-list"].children.length, 32);
  const before = h.requests.length;
  assert.throws(() => h.context.renderStorage({}), /Storage observation is invalid/);
  assert.equal(h.elements["device-list"].children.length, 32, "Refusal must happen before partial DOM changes");
  assert.equal(h.requests.length, before);
}

async function editorFixture() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)));
  fillPolicy(h.elements);
  const original = h.context.buildServiceAddition(null, h.context.buildPolicyProposal());
  const c = JSON.parse(JSON.stringify(original));
  c.shares.users.push({ id: "user-2", name: "writer" });
  c.shares.shares[0].grants.push({ user_id: "user-2", access: "rw" });
  c.shares.shares.push({ id: "share-2", name: "Other", volume_id: "volume-1", relative_path: "other", grants: [{ user_id: "user-2", access: "rw" }] });
  c.nfs.exports[0].clients.push({ ...c.nfs.exports[0].clients[0], network: "192.0.2.11/32", access: "rw" });
  c.nfs.exports.push({ ...structuredClone(c.nfs.exports[0]), id: "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", relative_path: "other" });
  const values = Object.fromEntries(Object.entries(h.elements).filter(([id]) => id.startsWith("policy-")).map(([id, element]) => [id.slice(7), element.value]));
  return { c, values, ...h };
}

async function testServiceEditingContracts() {
  const { context, c, values } = await editorFixture();
  const initial = structuredClone(c);
  const edit = (action, target, overrides = {}) => JSON.parse(JSON.stringify(context.buildServiceEdit(c, action, target, { ...values, ...overrides }).configuration));
  const smb = "smb:share-1", nfs = `nfs:${c.nfs.exports[0].id}`;
  const shared = (result) => {
    assert.equal(result.revision, 2);
    assert.equal(result.shares.revision, 2);
    assert.equal(result.nfs.revision, 2);
    assert.equal(result.nfs.volume_revision, 2);
    assert.deepEqual(c, initial, "source snapshot mutated");
  };
  let result = edit("smb-properties", smb, { name: "Renamed", path: "new-folder" }); shared(result);
  assert.equal(result.shares.shares[0].id, "share-1");
  assert.equal(result.shares.shares[0].relative_path, "new-folder");
  assert.deepEqual(result.shares.shares[0].grants, c.shares.shares[0].grants);
  assert.deepEqual(result.shares.shares[1], c.shares.shares[1]);
  assert.deepEqual(result.nfs.exports, c.nfs.exports);
  result = edit("smb-grant-upsert", smb, { "smb-access": "rw" }); shared(result);
  assert.deepEqual(result.shares.shares[0].grants, [{ user_id: "user-1", access: "rw" }, c.shares.shares[0].grants[1]]);
  assert.deepEqual(result.nfs.exports, c.nfs.exports);
  result = edit("smb-grant-upsert", smb, { user: "newreader" }); shared(result);
  assert.equal(result.shares.users[2].name, "newreader");
  assert.equal(result.shares.shares[0].grants.length, 3);
  assert.deepEqual(result.shares.shares[0].grants.slice(0, 2), c.shares.shares[0].grants);
  result = edit("smb-grant-remove", smb); shared(result);
  assert.deepEqual(result.shares.shares[0].grants, [c.shares.shares[0].grants[1]]);
  assert.deepEqual(result.shares.users, c.shares.users);
  result = edit("smb-remove", smb); shared(result);
  assert.deepEqual(result.shares.shares, [c.shares.shares[1]]);
  assert.deepEqual(result.shares.volumes, c.shares.volumes);
  assert.deepEqual(result.shares.users, c.shares.users);
  assert.deepEqual(result.nfs.exports, c.nfs.exports, "SMB removal touched NFS");
  result = edit("nfs-properties", nfs, { path: "new-nfs-path" }); shared(result);
  assert.equal(result.nfs.exports[0].id, c.nfs.exports[0].id);
  assert.deepEqual(result.nfs.exports[0].clients, c.nfs.exports[0].clients);
  assert.deepEqual(result.shares.shares, c.shares.shares);
  result = edit("nfs-client-upsert", nfs, { "nfs-access": "rw", uid: "1000", gid: "1000" }); shared(result);
  assert.equal(result.nfs.exports[0].clients[0].anonymous_uid, 1000);
  assert.deepEqual(result.nfs.exports[0].clients[1], c.nfs.exports[0].clients[1]);
  assert.deepEqual(result.nfs.exports[1], c.nfs.exports[1]);
  result = edit("nfs-client-upsert", nfs, { network: "192.0.2.12/32" }); shared(result);
  assert.equal(result.nfs.exports[0].clients.length, 3);
  assert.deepEqual(result.nfs.exports[0].clients.slice(0, 2), c.nfs.exports[0].clients);
  result = edit("nfs-client-remove", nfs); shared(result);
  assert.deepEqual(result.nfs.exports[0].clients, [c.nfs.exports[0].clients[1]]);
  result = edit("nfs-remove", nfs); shared(result);
  assert.deepEqual(result.nfs.exports, [c.nfs.exports[1]]);
  assert.deepEqual(result.shares, { ...c.shares, revision: 2 });
  result = edit("nfs-add", "", { path: "independent", "export-id": "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee" }); shared(result);
  assert.deepEqual(result.nfs.exports.slice(0, 2), c.nfs.exports);
  assert.deepEqual(result.shares, { ...c.shares, revision: 2 });
  assert.equal(result.nfs.exports[2].relative_path, "independent");
  for (const [action, target, overrides] of [
    ["smb-remove", "smb:missing", {}], ["smb-remove", nfs, {}], ["nfs-remove", smb, {}],
    ["smb-properties", smb, {}], ["smb-properties", smb, { name: "Other" }],
    ["smb-grant-remove", smb, { user: "missing" }], ["smb-grant-remove", "smb:share-2", { user: "writer" }],
    ["nfs-client-remove", nfs, { network: "192.0.2.99/32" }], ["nfs-add", "", {}],
    ["nfs-client-upsert", nfs, { uid: "0" }], ["nfs-client-upsert", nfs, { gid: "4294967295" }],
  ]) assert.throws(() => edit(action, target, overrides));
  const only = structuredClone(c); only.nfs.exports[0].clients.splice(1);
  assert.throws(() => context.buildServiceEdit(only, "nfs-client-remove", nfs, values), /last client/);
  const standalone = context.buildServiceEdit(null, "nfs-add", "", values).configuration;
  assert.equal(standalone.shares.shares.length, 0);
  assert.equal(standalone.shares.users.length, 0);
  assert.equal(standalone.nfs.exports.length, 1);
}

async function testServiceEditorInteraction() {
  const { c } = await editorFixture();
  let stored = c;
  const { context, elements, requests } = await serviceHarness((options) => {
    if (options.method === "PUT") { stored = JSON.parse(options.body); return jsonResponse(serviceSaved(stored.revision)); }
    return jsonResponse(serviceReply(stored));
  });
  fillPolicy(elements); await context.loadServicePolicy();
  assert.equal(elements["service-target"].children.length, 7, "shares, exports and desired user references are selectable");
  elements["service-target"].value = "smb:share-1";
  context.selectServiceTarget();
  assert.equal(elements["policy-name"].value, "Books");
  assert.equal(elements["service-member"].children.length, 3);
  elements["service-member"].value = "user-2"; context.selectServiceMember();
  assert.equal(elements["policy-user"].value, "writer");
  assert.equal(elements["policy-smb-access"].value, "rw");
  elements["service-action"].value = "smb-remove"; context.selectServiceAction();
  await context.prepareServiceEdit();
  assert.match(elements["service-change"].textContent, /Remove only SMB.*does not revoke NFS/);
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
  await context.saveServiceChange();
  assert.deepEqual(stored.nfs.exports, c.nfs.exports);
  assert.equal(stored.shares.shares.length, 1);
  assert.equal(elements["service-target"].value, "", "selection resets after commit");
  elements["service-target"].value = `nfs:${c.nfs.exports[0].id}`;
  context.selectServiceTarget();
  assert.equal(elements["policy-nfs-enabled"].value, "on");
  elements["service-member"].value = "192.0.2.11/32"; context.selectServiceMember();
  assert.equal(elements["policy-network"].value, "192.0.2.11/32");
  assert.equal(elements["policy-nfs-access"].value, "rw");
  elements["service-action"].value = "nfs-client-remove"; context.selectServiceAction();
  await context.prepareServiceEdit();
  assert.equal(elements["service-save"].disabled, false);
  // A changed action invalidates the candidate even if the form is untouched.
  elements["service-action"].value = "nfs-remove"; context.selectServiceAction();
  await context.saveServiceChange();
  assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
  context.showAuthUnavailable();
  assert.equal(elements["service-target"].children.length, 1);
  assert.equal(elements["service-member"].children.length, 1);
  assert.equal(elements["service-editor"].disabled, true);
}

async function testServiceUserReferenceContracts() {
  const { context, c, values } = await editorFixture();
  const original = structuredClone(c);
  const edit = (baseline, action, target, overrides = {}) =>
    JSON.parse(JSON.stringify(context.buildServiceEdit(baseline, action, target, { ...values, ...overrides }).configuration));
  const added = edit(c, "user-add", "smb:share-1", { user: "newreader", uuid: "not-used", path: "not-used" });
  assert.equal(added.shares.users.length, 3);
  assert.deepEqual(added.shares.users.slice(0, 2), c.shares.users);
  assert.deepEqual(added.shares.shares, c.shares.shares, "adding a reference must grant nothing");
  assert.deepEqual(added.shares.volumes, c.shares.volumes);
  assert.deepEqual(added.nfs, { ...c.nfs, revision: 2, volume_revision: 2 });
  assert.equal(added.revision, 2); assert.equal(added.shares.revision, 2);
  assert.deepEqual(c, original, "reference edits must not mutate the loaded baseline");
  assert.deepEqual(Array.from(context.describeServiceChanges(c, added), (r) => r.kind), ["User reference"]);
  const created = added.shares.users[2];
  // Removal is bound to selected ID, never a stale username in the form.
  const removed = edit(added, "user-remove", `user:${created.id}`, { user: "writer" });
  assert.deepEqual(removed.shares.users, c.shares.users);
  assert.deepEqual(removed.shares.shares, c.shares.shares);
  assert.deepEqual(removed.nfs, { ...c.nfs, revision: 3, volume_revision: 3 });
  assert.deepEqual(Array.from(context.describeServiceChanges(added, removed), (r) => r.kind), ["User reference"]);
  for (const target of ["user:user-1", "user:user-2"]) {
    assert.throws(() => edit(c, "user-remove", target), /still has SMB grants/);
  }
  for (const target of ["user:missing", "smb:share-1", `nfs:${c.nfs.exports[0].id}`, ""]) {
    assert.throws(() => edit(c, "user-remove", target));
  }
  for (const user of ["", "root", "nobody", "phantowd", "Upper", "1reader", "reader name", "reader/../", "a".repeat(33), "é", null, 3]) {
    assert.throws(() => edit(c, "user-add", "", { user }));
  }
  assert.throws(() => edit(c, "user-add", "", { user: "reader" }), /already/);
  assert.throws(() => edit(c, "user-rename", "user:user-1", { user: "renamed" }));
  assert.throws(() => edit(c, "", "user:user-1"), /explicit change/);
  const full = structuredClone(c);
  for (let i = 0; i < 125; i++) full.shares.users.push({ id: `unused-${i}`, name: `unused${i}` });
  const maximum = edit(full, "user-add", "", { user: "a".repeat(32) });
  assert.equal(maximum.shares.users.length, 128);
  assert.throws(() => edit(maximum, "user-add", "", { user: "overlimit" }), /maximum/);
  const only = edit(null, "user-add", "", { user: "first" });
  assert.deepEqual(only.shares.volumes, []); assert.deepEqual(only.shares.shares, []); assert.deepEqual(only.nfs.exports, []);
  const empty = edit(only, "user-remove", `user:${only.shares.users[0].id}`);
  assert.deepEqual(empty.shares.users, []); assert.deepEqual(empty.shares.shares, []);
  context.checkedServiceReviewDocument(only); context.checkedServiceReviewDocument(empty);
}

async function testServiceUserReferenceInteraction() {
  const { c } = await editorFixture();
  let stored = c;
  const h = await serviceHarness((options) => {
    if (options.method === "PUT") { stored = JSON.parse(options.body); return jsonResponse(serviceSaved(stored.revision)); }
    return jsonResponse(serviceReply(stored));
  });
  const { context, elements, requests } = h;
  await context.loadServicePolicy();
  elements["service-target"].value = "user:user-2"; context.selectServiceTarget();
  assert.equal(elements["policy-user"].value, "writer");
  assert.equal(elements["service-action"].value, "", "selection must not default to removal");
  assert.equal(elements["service-member"].disabled, true);
  assert.match(elements["service-status"].textContent, /2 SMB share grant/);
  elements["service-action"].value = "user-remove"; context.selectServiceAction();
  const before = requests.length;
  await context.prepareServiceEdit();
  assert.equal(requests.length, before, "referenced deletion must fail before authentication/preview/PUT requests");
  assert.match(elements["service-status"].textContent, /still has SMB grants/);
  assert.equal(elements["service-save"].disabled, true);
  elements["service-target"].value = "smb:share-1"; context.selectServiceTarget();
  assert.equal(elements["service-member"].disabled, false, "normal rule editing must recover after selecting a user");
  elements["service-action"].value = "user-add"; context.selectServiceAction();
  elements["policy-user"].value = "newreader";
  elements["policy-uuid"].value = "not-used"; elements["policy-path"].value = "not-used";
  await context.prepareServiceEdit();
  assert.match(elements["service-change"].textContent, /without any grants.*does not create an account/i);
  assert.equal(requests.filter((r) => r.options?.method === "PUT").length, 0);
  assert.equal(elements["service-save"].disabled, false);
  await context.saveServiceChange();
  assert.equal(stored.shares.users.length, 3);
  assert.deepEqual(stored.shares.shares, c.shares.shares);
  const added = stored.shares.users.find((u) => u.name === "newreader");
  elements["service-target"].value = `user:${added.id}`; context.selectServiceTarget();
  elements["service-action"].value = "user-remove"; context.selectServiceAction();
  elements["policy-user"].value = "writer";
  await context.prepareServiceEdit();
  assert.match(elements["service-change"].textContent, /Remove only unused desired reference newreader.*does not disable an account/i);
  await context.saveServiceChange();
  assert.deepEqual(stored.shares.users, c.shares.users);
  assert.deepEqual(stored.shares.shares, c.shares.shares);
  assert.deepEqual(stored.nfs.exports, c.nfs.exports);
  assert.equal(requests.filter((r) => r.options?.method === "PUT").length, 2);
  context.showAuthUnavailable();
  assert.equal(elements["service-target"].children.length, 1);
  assert.equal(elements["service-review"].hidden, true);
}

async function testServiceUserReferenceUncertainSave() {
  let stored = null;
  const h = await serviceHarness((options) => {
    if (options.method === "PUT") { stored = JSON.parse(options.body); return new Error("lost reply after commit"); }
    return jsonResponse(serviceReply(stored));
  });
  await h.context.loadServicePolicy();
  h.elements["service-action"].value = "user-add";
  h.elements["policy-user"].value = "newreader";
  await h.context.prepareServiceEdit(); await h.context.saveServiceChange();
  assert.match(h.elements["service-status"].textContent, /not confirmed.*may have committed/i);
  assert.equal(h.elements["service-save"].disabled, true);
  await h.context.prepareServiceEdit(); await h.context.saveServiceChange();
  assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
  await h.context.loadServicePolicy();
  assert.match(h.elements["service-status"].textContent, /complete attempted configuration.*confirmed saved/i);
  assert.deepEqual(stored.shares.shares, []); assert.equal(stored.shares.users.length, 1);
  assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
  process.stdout.write("Desired user-reference controls passed: explicit-create=true grants-preserved=true unused-only-remove=true no-default-delete=true unknown-save-no-retry=true accounts-provisioned=false.\n");
}

// Global panel sign-out is single-flight, authenticated/CSRF-bound, and never
// automatically retried when its response is lost or rejected.
for (const outcome of ["success", "uncertain", "rejected"]) {
  let ended = false;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const { elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !ended, setup_required: false });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/auth/logout-all") { ended = true; return pending; }
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected sign-out request: ${path}`);
  });
  const first = elements["logout-all"].listeners.get("click")();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements["logout-all"].disabled, true);
  assert.equal(elements.logout.disabled, true);
  await elements["logout-all"].listeners.get("click")();
  await elements.logout.listeners.get("click")();
  const writes = requests.filter(({ options }) => options?.method === "POST");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].path, "/api/v1/auth/logout-all");
  assert.equal(writes[0].options.headers["X-PhantoWD-CSRF"], "x".repeat(43));
  assert.equal(writes[0].options.credentials, "same-origin");
  assert.ok(writes[0].options.signal);
  release(outcome === "success" ? jsonResponse({ all_panel_sessions_revoked: true }) :
    outcome === "rejected" ? jsonResponse({}, 403) : new Error("lost response"));
  await first;
  assert.equal(elements["dashboard-content"].hidden, true);
  assert.equal(elements["auth-panel"].hidden, false);
  assert.equal(elements["logout-all"].disabled, false);
  assert.equal(requests.filter(({ options }) => options?.method === "POST").length, 1);
  if (outcome !== "success") assert.match(elements["auth-error"].textContent, /could not be confirmed/);
}

// Password changes carry no confirmation field, clear secrets immediately,
// permit only one POST and treat missing/malformed replies as uncertain.
for (const outcome of ["success", "wrong-current", "uncertain", "rejected", "malformed"]) {
  let ended = false;
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const { elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !ended, setup_required: false });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/auth/password") return pending;
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse(storageFixture());
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected password request: ${path}`);
  });
  elements["password-current"].value = "public old long passphrase";
  elements["password-new"].value = "public new long passphrase";
  elements["password-confirm"].value = "different confirmation";
  await elements["password-form"].listeners.get("submit")({ preventDefault() {} });
  assert.equal(requests.filter(({ options }) => options?.method === "POST").length, 0);
  elements["password-confirm"].value = elements["password-new"].value;
  const first = elements["password-form"].listeners.get("submit")({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  for (const field of ["current", "new", "confirm"]) assert.equal(elements[`password-${field}`].value, "");
  assert.equal(elements["password-submit"].disabled, true);
  await elements["password-form"].listeners.get("submit")({ preventDefault() {} });
  await elements["logout-all"].listeners.get("click")();
  const writes = requests.filter(({ options }) => options?.method === "POST");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].path, "/api/v1/auth/password");
  assert.deepEqual(JSON.parse(writes[0].options.body), { current_password: "public old long passphrase", new_password: "public new long passphrase" });
  assert.equal(writes[0].options.headers["X-PhantoWD-CSRF"], "x".repeat(43));
  assert.equal(writes[0].options.credentials, "same-origin");
  assert.ok(writes[0].options.signal);
  ended = outcome === "success";
  release(outcome === "success" ? jsonResponse({ password_changed: true, reauthentication_required: true, all_panel_sessions_revoked: true }) :
    outcome === "wrong-current" ? jsonResponse({ error: "current_password_invalid" }, 401) :
      outcome === "rejected" ? jsonResponse({}, 403) : outcome === "malformed" ? jsonResponse({}) : new Error("lost reply"));
  await first;
  assert.equal(elements["password-submit"].disabled, false);
  assert.equal(requests.filter(({ options }) => options?.method === "POST").length, 1);
  if (outcome === "wrong-current") {
    assert.equal(elements["dashboard-content"].hidden, false);
    assert.match(elements["password-status"].textContent, /not correct/);
  } else {
    assert.equal(elements["dashboard-content"].hidden, true);
    assert.match(elements["auth-error"].textContent, outcome === "success" ? /Password changed/ : /could not be confirmed/);
  }
}

async function testDesiredChangeReview() {
  const { context, elements, requests } = await serviceHarness(() => jsonResponse(serviceReply(null)));
  fillPolicy(elements);
  const proposal = context.buildPolicyProposal();
  const c = context.buildServiceAddition(null, proposal);
  const changes = context.describeServiceChanges(null, c);
  assert.equal(changes.length, 6, "first policy includes volume, user, SMB definition/grant and NFS definition/client");
  assert.equal(new Set(changes.map((r) => r.kind)).size, 6);
  assert.ok(changes.every((r) => r.before === "Not defined"));
  await context.loadServicePolicy();
  await context.prepareServiceAddition();
  assert.equal(elements["service-diff"].children.length, 6);
  assert.match(elements["service-diff-summary"].textContent, /6.*desired.*not effective/i);
  assert.equal(requests.filter((r) => r.options?.method === "PUT").length, 0, "review never saves");
  context.invalidateServiceDraft();
  assert.equal(elements["service-diff"].children.length, 0);
  assert.equal(elements["service-diff-summary"].textContent, "");
}

async function testDesiredChangeReviewEdits() {
  const { context, c, values } = await editorFixture();
  const initial = JSON.stringify(c);
  const smb = "smb:share-1", nfs = `nfs:${c.nfs.exports[0].id}`;
  for (const [action, target, overrides, kinds] of [
    ["smb-properties", smb, { name: "Renamed", path: "new-folder" }, ["SMB definition"]],
    ["smb-properties", smb, { uuid: "22222222-2222-3333-4444-555555555555" }, ["SMB definition", "Volume reference"]],
    ["smb-grant-upsert", smb, { "smb-access": "rw" }, ["SMB grant"]],
    ["smb-grant-upsert", smb, { user: "newreader" }, ["SMB grant", "User reference"]],
    ["smb-grant-remove", smb, {}, ["SMB grant"]],
    ["smb-remove", smb, {}, ["SMB definition", "SMB grant", "SMB grant"]],
    ["nfs-properties", nfs, { path: "new-folder" }, ["NFS definition"]],
    ["nfs-client-upsert", nfs, { "nfs-access": "rw", squash: "root", uid: "1000", gid: "1001", security: "krb5p" }, ["NFS client"]],
    ["nfs-client-upsert", nfs, { network: "2001:db8::/64" }, ["NFS client"]],
    ["nfs-client-remove", nfs, {}, ["NFS client"]],
    ["nfs-remove", nfs, {}, ["NFS definition", "NFS client", "NFS client"]],
    ["nfs-add", "", { "export-id": "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee" }, ["NFS definition", "NFS client"]],
  ]) {
    const next = context.buildServiceEdit(c, action, target, { ...values, ...overrides }).configuration;
    const rows = JSON.parse(JSON.stringify(context.describeServiceChanges(c, next)));
    assert.deepEqual(rows.map((r) => r.kind).sort(), kinds.sort(), action);
    assert.equal(JSON.stringify(c), initial, "comparison never mutates baseline");
    if (action.endsWith("remove")) assert.ok(rows.every((r) => r.after === "Not defined"));
    if (action === "nfs-client-upsert" && overrides.security) {
      assert.match(rows[0].before, /Read only.*\nMap all users to 65534:65534.*\nSecurity: AUTH_SYS/s);
      assert.match(rows[0].after, /Read and write.*\nMap root only to 1000:1001.*\nSecurity: Kerberos privacy/s);
    }
  }
  const reordered = structuredClone(c);
  reordered.shares.volumes.reverse(); reordered.shares.users.reverse(); reordered.shares.shares.reverse();
  reordered.shares.shares.forEach((s) => s.grants.reverse());
  reordered.nfs.exports.reverse(); reordered.nfs.exports.forEach((e) => e.clients.reverse());
  reordered.revision = reordered.shares.revision = reordered.nfs.revision = reordered.nfs.volume_revision = 2;
  assert.equal(context.describeServiceChanges(c, reordered).length, 0, "order and revision alone are not access changes");
  const ambiguous = structuredClone(c);
  ambiguous.nfs.exports[0].clients.push(structuredClone(ambiguous.nfs.exports[0].clients[0]));
  assert.throws(() => context.describeServiceChanges(c, ambiguous), /Ambiguous/);
  assert.throws(() => context.describeServiceChanges(undefined, c));
  assert.throws(() => context.describeServiceChanges(c, null));
  const renamedUser = structuredClone(c); renamedUser.shares.users[0].name = "renamed";
  const renamedRows = JSON.parse(JSON.stringify(context.describeServiceChanges(c, renamedUser)));
  assert.deepEqual(renamedRows.map((r) => r.kind).sort(), ["SMB grant", "User reference"].sort());
}

async function testDesiredChangeReviewBoundsAndRendering() {
  const { context, c, elements } = await editorFixture();
  const before = structuredClone(c);
  before.shares.users = Array.from({ length: 16 }, (_, i) => ({ id: `user-${i}`, name: `reader${i}` }));
  before.shares.shares = Array.from({ length: 32 }, (_, i) => ({ id: `share-${i}`, name: `Share${i}`,
    volume_id: before.shares.volumes[0].id, relative_path: `folder${i}`,
    grants: before.shares.users.slice(0, 15).map((u) => ({ user_id: u.id, access: "ro" })) }));
  const after = structuredClone(before);
  after.shares.shares.forEach((s) => { s.name += "Changed"; s.grants.forEach((g) => { g.access = "rw"; }); });
  const rows = context.describeServiceChanges(before, after);
  assert.equal(rows.length, 512, "complete bounded review at exact limit");
  context.renderServiceChanges(rows);
  assert.equal(elements["service-diff"].children.length, 512);
  before.shares.shares[0].grants.push({ user_id: "user-15", access: "ro" });
  after.shares.shares[0].grants.push({ user_id: "user-15", access: "rw" });
  assert.throws(() => context.describeServiceChanges(before, after), /More than 512/);
  const h = await serviceHarness(() => jsonResponse(serviceReply(before)));
  await h.context.loadServicePolicy();
  await h.context.previewServiceChange(() => ({ configuration: after, summary: "synthetic bulk change" }));
  assert.equal(h.elements["service-save"].disabled, true);
  assert.equal(h.elements["service-review"].hidden, true);
  assert.equal(h.elements["service-diff"].children.length, 0, "refusal never exposes a truncated review");
  assert.match(h.elements["service-status"].textContent, /More than 512/);
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);

  const unsafeText = structuredClone(c);
  unsafeText.shares.shares[0].name = "<img src=x onerror=alert(1)>";
  unsafeText.shares.shares[0].relative_path = "<script>fixture only</script>";
  context.renderServiceChanges(context.describeServiceChanges(c, unsafeText));
  assert.equal(elements["service-diff"].children.length, 1);
  const cells = elements["service-diff"].children[0].children;
  assert.equal(cells.length, 3);
  assert.equal(cells[0].attributes.get("scope"), "row");
  assert.match(cells[2].textContent, /<img.*<script>/s);
  assert.equal(cells[2].children.length, 0, "policy markup remains literal text, not child elements");
  assert.match(markup, /<caption>Desired policy changes/);
  assert.match(markup, /role="region" aria-label="Desired policy before and after" tabindex="0"/);
  context.clearServicePolicy();
  assert.equal(elements["service-diff"].children.length, 0);
}

async function testCrossProtocolPairRelationships() {
  const { context, c, values } = await editorFixture();
  const original = JSON.stringify(c);
  const project = (before, after) => JSON.parse(JSON.stringify(context.describeServiceOverlaps(before, after)));
  const review = project(c, c);
  assert.equal(review.baseline_count, 2);
  assert.equal(review.candidate_count, 2);
  assert.equal(review.pair_count, 2);
  assert.equal(review.omitted_count, 0);
  assert.equal(review.rows.length, 2);
  assert.ok(review.rows.every((r) => r.before === r.after && /Same configured folder/.test(r.after)));
  for (const [smbPath, nfsPath, relationship] of [
    ["books", "books", "Same configured folder"],
    ["books", "books/subfolder", "SMB folder contains NFS folder"],
    ["books/subfolder/deep", "books", "NFS folder contains SMB folder"],
    [".", "books", "SMB folder contains NFS folder"],
    ["books", ".", "NFS folder contains SMB folder"],
    [".", ".", "Same configured folder"],
    ["books", "bookstore", null],
    ["books", "books-old", null],
    ["books", "Books", null],
    ["caf\u00e9", "cafe\u0301", null],
  ]) {
    const candidate = structuredClone(c);
    candidate.shares.shares = [candidate.shares.shares[0]];
    candidate.nfs.exports = [candidate.nfs.exports[0]];
    candidate.shares.shares[0].relative_path = smbPath;
    candidate.nfs.exports[0].relative_path = nfsPath;
    const result = project(null, candidate);
    assert.equal(result.candidate_count, relationship === null ? 0 : 1, `${smbPath} / ${nfsPath}`);
    if (relationship !== null) {
      assert.match(result.rows[0].before, /No lexical overlap/);
      assert.ok(result.rows[0].after.includes(relationship));
    }
  }
  const distinctVolume = structuredClone(c);
  distinctVolume.shares.volumes.push({ id: "volume-2", filesystem_uuid: "22222222-2222-3333-4444-555555555555" });
  distinctVolume.nfs.exports.forEach((e) => { e.volume_id = "volume-2"; });
  assert.equal(project(null, distinctVolume).candidate_count, 0, "matching folder strings on different volume references are not a lexical pair");
  const removed = context.buildServiceEdit(c, "smb-remove", "smb:share-1", values).configuration;
  const removedReview = project(c, removed);
  assert.equal(removedReview.baseline_count, 2);
  assert.equal(removedReview.candidate_count, 1);
  assert.equal(removedReview.pair_count, 2, "removed overlap remains visible in baseline");
  assert.equal(removedReview.rows.filter((r) => /No lexical overlap/.test(r.after)).length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(removed.nfs)), { ...c.nfs, revision: 2, volume_revision: 2 }, "SMB removal retains NFS policy");
  const reordered = structuredClone(c);
  reordered.shares.shares.reverse(); reordered.nfs.exports.reverse();
  assert.deepEqual(project(reordered, reordered), review, "pair ordering does not depend on collection positions");
  assert.equal(JSON.stringify(c), original, "advice does not mutate source policy");
  for (const path of ["", "/", "/books", "books/", "books//sub", "books/./sub", "books/../sub"]) {
    const malformed = structuredClone(c); malformed.nfs.exports[0].relative_path = path;
    assert.throws(() => context.describeServiceOverlaps(c, malformed), /Noncanonical/);
  }
  assert.throws(() => context.describeServiceOverlaps(undefined, c));
  assert.throws(() => context.describeServiceOverlaps(c, null));
}

async function testCrossProtocolPairBoundsAndRendering() {
  const { context, c } = await editorFixture();
  const large = structuredClone(c);
  large.shares.shares = Array.from({ length: 128 }, (_, i) => ({ ...structuredClone(c.shares.shares[0]),
    id: `share-${i}`, name: `Share${i}`, relative_path: "." }));
  large.nfs.exports = Array.from({ length: 128 }, (_, i) => ({ ...structuredClone(c.nfs.exports[0]),
    id: `00000000-0000-0000-0000-${String(i).padStart(12, "0")}`, relative_path: "books" }));
  const review = context.describeServiceOverlaps(large, large);
  assert.equal(review.baseline_count, 16384);
  assert.equal(review.candidate_count, 16384);
  assert.equal(review.pair_count, 16384);
  assert.equal(review.rows.length, 64, "retained details/DOM are bounded independently of pair census");
  assert.equal(review.omitted_count, 16320);
  const exactly64 = structuredClone(large);
  exactly64.shares.shares = exactly64.shares.shares.slice(0, 1);
  exactly64.nfs.exports = exactly64.nfs.exports.slice(0, 64);
  assert.equal(context.describeServiceOverlaps(null, exactly64).omitted_count, 0);
  exactly64.nfs.exports.push(large.nfs.exports[64]);
  assert.equal(context.describeServiceOverlaps(null, exactly64).omitted_count, 1);
  const disjointIDs = structuredClone(large);
  disjointIDs.shares.shares.forEach((s) => { s.id += "-new"; });
  disjointIDs.nfs.exports.forEach((e) => { e.id = "10000000" + e.id.slice(8); });
  const union = context.describeServiceOverlaps(large, disjointIDs);
  assert.equal(union.pair_count, 32768, "baseline/candidate pair union counted without materializing it");
  assert.equal(union.omitted_count, 32704);

  const h = await serviceHarness(() => jsonResponse(serviceReply(large)));
  await h.context.loadServicePolicy();
  const candidate = structuredClone(large);
  candidate.revision = candidate.shares.revision = candidate.nfs.revision = candidate.nfs.volume_revision = 2;
  await h.context.previewServiceChange(() => ({ configuration: candidate, summary: "unchanged bounded advisory" }));
  assert.equal(h.elements["service-overlaps"].children.length, 64);
  assert.match(h.elements["service-overlap-summary"].textContent, /16384 baseline.*16384 candidate.*64 of 16384.*16320.*omitted/);
  assert.equal(h.elements["service-save"].disabled, false, "advisory detail limit does not block otherwise complete review");
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
  h.context.invalidateServiceDraft();
  assert.equal(h.elements["service-overlaps"].children.length, 0);
  assert.equal(h.elements["service-overlap-summary"].textContent, "");

  const unsafe = structuredClone(c);
  unsafe.shares.shares[0].name = "<img src=x onerror=alert(1)>";
  unsafe.shares.shares[0].relative_path = unsafe.nfs.exports[0].relative_path = "<script>fixture</script>";
  const unsafeReview = h.context.describeServiceOverlaps(null, unsafe);
  h.context.renderServiceOverlaps(unsafeReview);
  const cells = h.elements["service-overlaps"].children[0].children;
  assert.equal(cells[0].attributes.get("scope"), "row");
  assert.match(cells[2].textContent, /<img.*<script>/s);
  assert.equal(cells[2].children.length, 0, "advisory values are literal text");
  assert.match(markup, /<caption>Configured folder pairs/);
  assert.match(markup, /aria-label="Configured SMB and NFS folder overlap" tabindex="0"/);
  assert.match(markup, /Removing an SMB grant or definition does not revoke NFS/);
  h.context.clearServicePolicy();
  assert.equal(h.elements["service-overlaps"].children.length, 0);
  assert.equal(h.elements["service-overlap-summary"].textContent, "");
}

await testDesiredChangeReview();
await testDesiredChangeReviewEdits();
await testDesiredChangeReviewBoundsAndRendering();
await testCrossProtocolPairRelationships();
await testCrossProtocolPairBoundsAndRendering();

function backupFixture(configuration) {
  return { format: "phantowd-file-service-backup", schema_version: 1, configuration };
}

function backupFile(text) {
  const bytes = typeof text === "string" ? new TextEncoder().encode(text) : text;
  return { size: bytes.byteLength, arrayBuffer: async () => bytes.slice().buffer };
}

function restoreFixture(c, expected) {
  return { schema_version: 1, scope: "file-service-restore-preview-only", expected_revision: expected,
    configuration: c, preview: policyFixture(), saved: false, applied: false, runtime_validated: false, activation_available: false };
}

async function testServiceBackupDownloadAndPrivacy() {
  const c = { format: "phantowd-file-service-config", schema_version: 1, revision: 1,
    shares: { ...savedFixture().configuration, revision: 1 },
    nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 1, volume_revision: 1, exports: [] } };
  for (const changed of [false, true]) {
    const backup = backupFixture(structuredClone(c));
    if (changed) backup.configuration.shares.shares[0].name += "-changed";
    const h = await serviceHarness(() => jsonResponse(serviceReply(c)), undefined, undefined, () => jsonResponse(backup));
    await h.context.exportServiceBackup();
    assert.equal(h.requests.some((r) => r.path.endsWith("/backup")), false, "no export before explicit load");
    await h.context.loadServicePolicy();
    await h.elements["service-backup-download"].listeners.get("click")();
    assert.equal(h.document.downloads.length, changed ? 0 : 1);
    assert.equal(h.requests.some((r) => ["POST", "PUT"].includes(r.options?.method)), false, "export must not request CSRF, preview or mutation");
    if (!changed) {
      assert.equal(h.document.downloads[0].filename, "phantowd-file-services.json");
      assert.deepEqual(JSON.parse(await h.document.blobs[0].text()), backup);
      assert.equal(h.document.body.children.length, 0, "temporary download anchor released");
      await new Promise((resolve) => setTimeout(resolve, 1));
      assert.deepEqual(h.document.revokedURLs, ["blob:fixture-1"]);
      assert.match(h.elements["service-status"].textContent, /not a data or credential backup/);
    } else assert.match(h.elements["service-status"].textContent, /changed/);
  }
  assert.match(markup, /Keep it private/);
  assert.match(markup, /not a complete device backup/);
}

async function testServiceRestoreRawPreviewAndExplicitSave() {
  let current = null;
  let uploaded;
  const c = { format: "phantowd-file-service-config", schema_version: 1, revision: 1,
    shares: { ...savedFixture().configuration, revision: 1 },
    nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 1, volume_revision: 1, exports: [] } };
  const h = await serviceHarness((options) => {
    if (options.method === "PUT") { current = JSON.parse(options.body); return jsonResponse(serviceSaved(current.revision)); }
    return jsonResponse(serviceReply(current));
  }, undefined, undefined, (_path, options) => { uploaded = options; return jsonResponse(restoreFixture(c, 0)); });
  await h.context.loadServicePolicy();
  const text = JSON.stringify(backupFixture(c), null, 2);
  h.elements["service-restore-file"].files = [backupFile(text)];
  h.elements["service-restore-file"].listeners.get("change")();
  await h.elements["service-restore-preview"].listeners.get("click")();
  assert.equal(uploaded.body, text, "original whitespace and duplicate-key evidence must not be collapsed by JSON.parse");
  assert.equal(uploaded.headers["X-PhantoWD-Expected-Revision"], "0");
  assert.equal(uploaded.headers["X-PhantoWD-CSRF"], "fixture-only");
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false, "import selection/preview never saves automatically");
  assert.equal(h.elements["service-save"].disabled, false);
  assert.match(h.elements["service-change"].textContent, /Replace the complete.*Definitions and grants absent/);
  await h.context.saveServiceChange();
  assert.deepEqual(current, c);
  assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
  assert.match(h.elements["service-status"].textContent, /confirmed saved.*No services/);
}

async function testServiceRestoreRefusalsAndOriginalEncoding() {
  for (const kind of ["oversize", "empty", "invalid-utf8", "BOM", "duplicates", "conflict", "unsupported-response"]) {
    let upload;
    const h = await serviceHarness(() => jsonResponse(serviceReply(null)), undefined, undefined, (_path, options) => {
      upload = options;
      return kind === "unsupported-response" ? jsonResponse({ saved: true }) : jsonResponse({}, kind === "conflict" ? 409 : 422);
    });
    await h.context.loadServicePolicy();
    let file = backupFile(kind === "BOM" ? "\ufeff{}" : kind === "duplicates" ? '{"format":"a","format":"b"}' : "{}");
    if (kind === "invalid-utf8") file = backupFile(new Uint8Array([0x7b, 0xff, 0x7d]));
    if (kind === "oversize") file = { size: 525057, arrayBuffer: () => { throw new Error("oversize file must not be read"); } };
    if (kind === "empty") file = { size: 0, arrayBuffer: () => { throw new Error("empty file must not be read"); } };
    h.elements["service-restore-file"].files = [file];
    await h.context.previewServiceRestore();
    assert.equal(Boolean(upload), !["oversize", "empty", "invalid-utf8"].includes(kind));
    if (kind === "BOM") assert.equal(upload.body.charCodeAt(0), 0xfeff, "BOM is not silently removed");
    if (kind === "duplicates") assert.equal(upload.body, '{"format":"a","format":"b"}');
    assert.equal(h.elements["service-save"].disabled, true);
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
  }
}

async function testServiceRestoreLateFileAndPreviewRefusal() {
  for (const boundary of ["file", "preview"]) {
    let finish, reads = 0;
    const pending = new Promise((resolve) => { finish = resolve; });
    const h = await serviceHarness(() => jsonResponse(serviceReply(null)), undefined, undefined, () => { reads++; return pending; });
    await h.context.loadServicePolicy();
    const file = backupFile("{}");
    if (boundary === "file") file.arrayBuffer = () => pending;
    h.elements["service-restore-file"].files = [file];
    const operation = h.context.previewServiceRestore();
    await new Promise((resolve) => setImmediate(resolve));
    await h.context.previewServiceRestore();
    assert.equal(reads, boundary === "file" ? 0 : 1, "only one import operation owns file/HTTP reads");
    h.context.clearServicePolicy();
    if (boundary === "file") finish(new TextEncoder().encode("{}").buffer);
    else finish(jsonResponse(restoreFixture({ revision: 1 }, 0)));
    await operation;
    assert.equal(h.elements["service-save"].disabled, true);
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.elements["service-document"].textContent, "");
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
    if (boundary === "file") assert.equal(reads, 0, "retired file read must not invoke HTTP");
  }
}

await testServiceBackupDownloadAndPrivacy();
await testServiceRestoreRawPreviewAndExplicitSave();
await testServiceRestoreRefusalsAndOriginalEncoding();
await testServiceRestoreLateFileAndPreviewRefusal();

async function testServiceBackupCancellationAndReadDeadline() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)));
  const controller = new AbortController();
  let finish;
  const file = { arrayBuffer: () => new Promise((resolve) => { finish = resolve; }) };
  const read = h.context.readServiceBackupFile(file, controller.signal);
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  await assert.rejects(read, (failure) => failure.name === "AbortError");
  finish(new Uint8Array([123, 125]).buffer);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.requests.some((r) => r.path.endsWith("/restore-preview")), false);

  let expire;
  const timed = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/file-services/configuration") return jsonResponse(serviceReply(null));
    return snapshotResponse(path);
  }, { setTimeout: (callback) => { expire = callback; return 1; }, clearTimeout() {} });
  await timed.context.loadServicePolicy();
  let settle;
  timed.elements["service-restore-file"].files = [{ size: 2, arrayBuffer: () => new Promise((resolve) => { settle = resolve; }) }];
  const operation = timed.context.previewServiceRestore();
  await new Promise((resolve) => setImmediate(resolve));
  expire();
  await operation;
  assert.equal(timed.elements["service-load"].disabled, false, "deadline releases the UI gate even if file read has not settled");
  assert.match(timed.elements["service-status"].textContent, /timed out.*No save/);
  settle(new TextEncoder().encode("{}").buffer);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(timed.requests.some((r) => r.path.endsWith("/restore-preview")), false, "late file read after timeout cannot submit");
}

await testServiceBackupCancellationAndReadDeadline();
async function testSanitizedSupportExportLifecycle() {
  let authenticated = true, unavailable = false, pending = false;
  const releases = [];
  const input = supportFixture();
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated });
    const domain = path.split("/").at(-1);
    if (!["system", "storage", "arrays", "mounts"].includes(domain)) throw new Error("unexpected support request");
    if (pending) return new Promise((resolve) => releases.push(() => resolve(jsonResponse(input[domain]))));
    if (unavailable && domain === "storage") return jsonResponse({ error: "PRIVATE-SENTINEL" }, 503);
    return jsonResponse(input[domain]);
  });
  await settleUI();
  assert.equal(h.elements["support-download"].disabled, false);
  const count = h.requests.length;
  h.elements["support-download"].listeners.get("click")();
  assert.equal(h.requests.length, count, "report export must not collect or authenticate again");
  assert.equal(h.document.downloads.length, 1);
  assert.equal(h.document.downloads[0].filename, "phantowd-sanitized-support-v1.json");
  const text = await h.document.blobs[0].text();
  assert.ok(!text.includes("PRIVATE-SENTINEL"));
  assert.equal(JSON.parse(text).observations.arrays.status, "partial");
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(h.document.revokedURLs.length, 1);
  assert.equal(h.document.body.children.length, 0, "download anchor must be removed");

  unavailable = true;
  await h.context.refreshSnapshot();
  h.context.exportSupportSnapshot();
  const partial = JSON.parse(await h.document.blobs.at(-1).text());
  assert.deepEqual(partial.observations.storage, { status: "unavailable" }, "failed refresh must never reuse prior storage values");
  assert.equal(partial.observations.system.status, "available");

  pending = true;
  const retired = h.context.refreshSnapshot();
  await settleUI();
  const downloads = h.document.downloads.length;
  assert.equal(h.elements["support-download"].disabled, true, "refresh retires previous report immediately");
  h.context.exportSupportSnapshot();
  assert.equal(h.document.downloads.length, downloads);
  authenticated = false;
  h.context.showAuthUnavailable();
  for (const release of releases) release();
  await retired;
  assert.equal(h.elements["support-download"].disabled, true, "retired late replies must not re-enable export");
  h.context.exportSupportSnapshot();
  assert.equal(h.document.downloads.length, downloads);
}

async function testSanitizedSupportDownloadFailure() {
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) : snapshotResponse(path));
  await settleUI();
  h.context.URL.createObjectURL = () => { throw new Error("PRIVATE-SENTINEL"); };
  const count = h.requests.length;
  h.context.exportSupportSnapshot();
  assert.equal(h.document.downloads.length, 0);
  assert.match(h.elements["support-status"].textContent, /could not be completed/);
  assert.ok(!h.elements["support-status"].textContent.includes("PRIVATE-SENTINEL"));
  assert.equal(h.elements["support-download"].disabled, false);
  assert.equal(h.requests.length, count);
  h.context.clearSnapshot("fixture logout boundary");
  assert.equal(h.elements["support-download"].disabled, true);
}

await testSanitizedSupportExportLifecycle();
await testSanitizedSupportDownloadFailure();

async function testMissingArrayListIsNotAnEmptyCurrentInventory() {
  let arrays = arraysFixture();
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/arrays" ? jsonResponse(arrays) : snapshotResponse(path, "current-kernel"));
  await settleUI();
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
  arrays = { ...arraysFixture(), array_count: 0, arrays: null };
  const before = h.requests.length;
  await h.context.refreshSnapshot();
  assert.equal(h.elements["array-count"].textContent, "RAID unavailable", "Missing RAID rows must not imply an empty kernel inventory");
  assert.equal(h.elements["kernel-value"].textContent, "Linux current-kernel");
  assert.equal(h.elements["mount-count"].textContent, "2 mounts");
  assert.equal(h.requests.length - before, 4);
}
await testMissingArrayListIsNotAnEmptyCurrentInventory();

async function testMissingMountListIsNotAnEmptyCurrentInventory() {
  let mounts = mountsFixture();
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/mounts" ? jsonResponse(mounts) : snapshotResponse(path, "current-kernel"));
  await settleUI();
  mounts = { ...mountsFixture(), mount_count: 0, mounts: null };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["mount-count"].textContent, "Mounts unavailable", "Missing mount rows must not imply an empty namespace");
  assert.equal(h.elements["kernel-value"].textContent, "Linux current-kernel");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
}
await testMissingMountListIsNotAnEmptyCurrentInventory();

async function testInvalidMemoryDoesNotBecomeAHealthySystemSample() {
  let system = systemFixture();
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/system" ? jsonResponse(system) : snapshotResponse(path));
  await settleUI();
  system = { ...systemFixture(), memory: { total_bytes: 256 * 1024 ** 2, available_bytes: -1 } };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["kernel-value"].textContent, "Unavailable", "Invalid memory must not leave a current system sample");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
  assert.equal(h.elements["mount-count"].textContent, "2 mounts");
  system = { ...systemFixture(), memory: { total_bytes: 256 * 1024 ** 2, available_bytes: 0 } };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["memory-value"].textContent, "0 MiB available", "A valid exhausted-memory sample is not missing data");
}
await testInvalidMemoryDoesNotBecomeAHealthySystemSample();

async function testInvalidPrivateArrayDetailCannotBecomeAnAvailableReport() {
  const arrays = { ...arraysFixture(), array_count: 1, arrays: [{ ...arraysFixture().arrays[0], members: [null] }] };
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/arrays" ? jsonResponse(arrays) : snapshotResponse(path));
  await settleUI();
  assert.equal(h.elements["array-count"].textContent, "RAID unavailable");
  const report = JSON.parse(new Script("supportSnapshot.serialize(Date.now())").runInContext(h.context));
  assert.equal(report.observations.arrays.status, "invalid", "Rejected private details must not yield an available projected report");
}
await testInvalidPrivateArrayDetailCannotBecomeAnAvailableReport();

async function testRemainingSnapshotDomainsRefuseMalformedEnvelopes() {
  const system = systemFixture(), arrays = arraysFixture(), mounts = mountsFixture();
  const groups = [
    { domain: "system", element: "kernel-value", empty: "Unavailable", values: [null, {}, [],
      { ...system, schema_version: 2 }, { ...system, memory: null }, { ...system, memory: [] },
      { ...system, memory: { ...system.memory, total_bytes: 0 } },
      { ...system, memory: { ...system.memory, total_bytes: "256" } },
      { ...system, memory: { ...system.memory, available_bytes: -1 } },
      { ...system, memory: { ...system.memory, available_bytes: system.memory.total_bytes + 1 } },
      { ...system, memory: { ...system.memory, available_bytes: "0" } },
      { ...system, uptime_seconds: -1 }, { ...system, uptime_seconds: "1" },
      { ...system, uptime_seconds: Number.MAX_SAFE_INTEGER + 1 },
      { ...system, flashable: "false" }, { ...system, hardware_validated: null }] },
    { domain: "arrays", element: "array-count", empty: "RAID unavailable", values: [null, {}, [],
      { ...arrays, schema_version: 2 }, { ...arrays, arrays: null }, { ...arrays, arrays: "PRIVATE-SENTINEL" },
      { ...arrays, read_only: false }, { ...arrays, block_devices_opened: true }, { ...arrays, disk_content_read: true },
      { ...arrays, mutations_performed: true }, { ...arrays, status: "PRIVATE-SENTINEL" },
      { ...arrays, array_count: "2" }, { ...arrays, array_count: 0 },
      { ...arrays, arrays: [null], array_count: 1 }, { ...arrays, arrays: [[]], array_count: 1 },
      { ...arrays, arrays: [{ ...arrays.arrays[0], health: "PRIVATE-SENTINEL" }], array_count: 1 },
      { ...arrays, status: "unavailable" }, { ...arrays, status: "unsupported" },
      { ...arrays, arrays: [{ ...arrays.arrays[0], members: [null] }], array_count: 1 },
      { ...arrays, arrays: [{ ...arrays.arrays[0], members: [[]] }], array_count: 1 },
      { ...arrays, arrays: [{ ...arrays.arrays[0], members: Array.from({ length: 33 }, () => ({ name: "PRIVATE-SENTINEL" })) }], array_count: 1 },
      { ...arrays, arrays: Array.from({ length: 17 }, () => arrays.arrays[0]), array_count: 17 }] },
    { domain: "mounts", element: "mount-count", empty: "Mounts unavailable", values: [null, {}, [],
      { ...mounts, schema_version: 2 }, { ...mounts, scope: "PRIVATE-SENTINEL" }, { ...mounts, mounts: null },
      { ...mounts, mounts: "PRIVATE-SENTINEL" }, { ...mounts, read_only: false },
      { ...mounts, filesystem_contents_read: true }, { ...mounts, mount_operations_performed: true },
      { ...mounts, mount_count: "2" }, { ...mounts, mount_count: 0 },
      { ...mounts, mounts: [null], mount_count: 1 }, { ...mounts, mounts: [[]], mount_count: 1 },
      { ...mounts, mounts: [{ ...mounts.mounts[0], read_only: "false" }], mount_count: 1 },
      { ...mounts, mounts: [{ ...mounts.mounts[0], filesystem: null }], mount_count: 1 },
      { ...mounts, mounts: Array.from({ length: 129 }, () => mounts.mounts[0]), mount_count: 129 }] },
  ];
  let payloads = { system, arrays, mounts }, round = 0;
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    const domain = path.split("/").at(-1);
    return domain === "storage" ? jsonResponse(storageFixture([blockFixture({ name: `fresh-${round}` })])) : jsonResponse(payloads[domain]);
  });
  await settleUI();
  for (const group of groups) for (const value of group.values) {
    round++;
    payloads = { system, arrays, mounts, [group.domain]: value };
    const before = h.requests.length;
    await h.context.refreshSnapshot();
    assert.equal(h.elements[group.element].textContent, group.empty, `${group.domain} invalid case ${round}`);
    assert.equal(h.elements["device-count"].textContent, "1 device");
    assert.equal(h.elements["device-list"].children[0].children[0].children[1].children[0].textContent, `fresh-${round}`, "Valid domains must not reuse old values");
    if (group.domain !== "system") assert.equal(h.elements["kernel-value"].textContent, "Linux 6.18.54");
    if (group.domain !== "arrays") assert.equal(h.elements["array-count"].textContent, "2 arrays");
    if (group.domain !== "mounts") assert.equal(h.elements["mount-count"].textContent, "2 mounts");
    assert.equal(h.requests.length - before, 4);
    const report = JSON.parse(new Script("supportSnapshot.serialize(Date.now())").runInContext(h.context));
    assert.equal(report.observations[group.domain].status, value === null ? "unavailable" : "invalid");
    assert.ok(!JSON.stringify(report).includes("PRIVATE-SENTINEL"));
  }
  for (const status of ["available", "partial", "unsupported", "unavailable"]) {
    payloads = { system, mounts, arrays: { ...arrays, status, array_count: 0, arrays: [] } };
    await h.context.refreshSnapshot();
    assert.equal(h.elements["array-count"].textContent, status === "available" ? "0 arrays" : `RAID ${status}`);
    assert.equal(JSON.parse(new Script("supportSnapshot.serialize(Date.now())").runInContext(h.context)).observations.arrays.status, status);
  }
  payloads = { system, arrays: { ...arrays, array_count: 16, arrays: Array.from({ length: 16 }, () => ({ ...arrays.arrays[0], members: Array.from({ length: 32 }, () => ({ name: "fixture" })) })) },
    mounts: { ...mounts, mount_count: 128, mounts: Array.from({ length: 128 }, () => mounts.mounts[0]) } };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["array-list"].children.length, 16);
  assert.equal(h.elements["mount-list"].children.length, 128);
  for (const [render, id, count] of [["renderArrays", "array-list", 16], ["renderMounts", "mount-list", 128]]) {
    assert.throws(() => h.context[render]({}), /observation is invalid/);
    assert.equal(h.elements[id].children.length, count, "Guard must refuse before changing any prior DOM row");
  }
  const kernel = h.elements["kernel-value"].textContent;
  assert.throws(() => h.context.renderSystem({}), /observation is invalid/);
  assert.equal(h.elements["kernel-value"].textContent, kernel);
  payloads = { system: {}, arrays: {}, mounts: {} };
  await h.context.refreshSnapshot();
  assert.equal(h.elements["device-count"].textContent, "1 device");
  assert.equal(h.elements["kernel-value"].textContent, "Unavailable");
  assert.equal(h.elements["array-count"].textContent, "RAID unavailable");
  assert.equal(h.elements["mount-count"].textContent, "Mounts unavailable");
  process.stdout.write(`Snapshot display-envelope controls passed: system=${groups[0].values.length} arrays=${groups[1].values.length} mounts=${groups[2].values.length} negative=${round} maxima=16/32/128.\n`);
}
await testRemainingSnapshotDomainsRefuseMalformedEnvelopes();

async function testOversizedSnapshotBodyIsNotParsedAsCurrentSystem() {
  let oversized = false, parsed = 0;
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system" && oversized) {
      const value = { ...systemFixture(), padding: "PRIVATE-SENTINEL".repeat(1200) };
      const response = jsonResponse(value);
      response.json = async () => { parsed++; return value; };
      return response;
    }
    return snapshotResponse(path, "fresh-kernel");
  });
  await settleUI();
  oversized = true;
  const before = h.requests.length;
  await h.context.refreshSnapshot();
  assert.equal(h.elements["kernel-value"].textContent, "Unavailable", "A system body above16KiB must refuse before parsing");
  assert.equal(parsed, 0, "Unbounded Response.json must never be invoked for snapshots");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
  assert.equal(h.elements["mount-count"].textContent, "2 mounts");
  assert.equal(h.requests.length - before, 4);
}
await testOversizedSnapshotBodyIsNotParsedAsCurrentSystem();

async function testInitialAuthBodyHasAFiniteReadDeadline() {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const timers = new Map();
  let id = 0;
  const h = await createHarness(async () => deferredJSONResponse(pending), {
    setTimeout: (callback, delay) => { const timer = ++id; timers.set(timer, { callback, delay }); return timer; },
    clearTimeout: (timer) => timers.delete(timer),
  });
  assert.equal(timers.size, 1, "Initial authentication status must not hang without a deadline");
  const deadline = [...timers.values()][0];
  assert.equal(deadline.delay, 10000);
  deadline.callback();
  await settleUI();
  assert.equal(h.elements["dashboard-content"].hidden, true);
  assert.equal(h.elements["auth-retry"].hidden, false);
  assert.equal(timers.size, 0);
  const before = h.requests.length;
  release({ authenticated: true });
  await settleUI();
  assert.equal(h.elements["dashboard-content"].hidden, true);
  assert.equal(h.requests.length, before);
}
await testInitialAuthBodyHasAFiniteReadDeadline();

async function testCredentialSubmissionHasOneFiniteDeadline() {
  for (const setup of [false, true]) {
    const timers = new Map();
    let timerID = 0, release;
    const pending = new Promise(resolve => { release = resolve; });
    const route = `/api/v1/auth/${setup ? "setup" : "login"}`;
    const h = await createHarness(async path => {
      if (path === route) return pending; // Deliberately ignores AbortSignal.
      if (path === "/api/v1/auth/status") return jsonResponse({ setup_required: setup, authenticated: false });
      return snapshotResponse(path);
    }, {
      setTimeout: (callback, delay) => { const id = ++timerID; timers.set(id, { callback, delay }); return id; },
      clearTimeout: id => timers.delete(id),
    });
    await settleUI();
    h.elements["auth-username"].value = "fixture-admin";
    h.elements["auth-password"].value = "fixture-only original passphrase";
    const submission = h.elements["auth-form"].listeners.get("submit")({ preventDefault() {} });
    await settleUI();
    const request = h.requests.find(request => request.path === route);
    assert.ok(request?.options.signal, "Credential POST must own a cancellation signal");
    assert.equal(timers.size, 1, "Credential POST must not wait indefinitely for response headers");
    const deadline = [...timers.values()][0];
    assert.equal(deadline.delay, 10000);
    deadline.callback();
    await submission;
    assert.equal(request.options.signal.aborted, true);
    assert.equal(h.elements["auth-submit"].disabled, false);
    assert.equal(h.elements["auth-password"].value, "");
    assert.equal(h.elements["dashboard-content"].hidden, true);
    assert.equal(h.elements["auth-form"].hidden, true, "Unknown submission needs a status reread, not blind resubmission");
    assert.equal(h.elements["auth-retry"].hidden, false);
    assert.match(h.elements["auth-error"].textContent, /not retried/i);
    assert.equal(timers.size, 0);
    const count = h.requests.length;
    release(jsonResponse({ authenticated: true }));
    await settleUI();
    assert.equal(h.requests.length, count, "Late POST completion must not reread state or publish a session");
    assert.equal(h.elements["dashboard-content"].hidden, true);
  }
}
await testCredentialSubmissionHasOneFiniteDeadline();

async function credentialHarness(setup, post, status) {
  const timers = new Map();
  let id = 0;
  const route = `/api/v1/auth/${setup ? "setup" : "login"}`;
  const h = await createHarness(async (path, options) => {
    if (path === route) return post(options);
    if (path === "/api/v1/auth/status") return status ? status(options) : jsonResponse({ setup_required: setup, authenticated: false });
    return snapshotResponse(path);
  }, {
    setTimeout: (callback, delay) => { const timer = ++id; timers.set(timer, { callback, delay }); return timer; },
    clearTimeout: timer => timers.delete(timer),
  });
  await settleUI();
  const submit = () => {
    h.elements["auth-username"].value = "fixture-admin";
    h.elements["auth-password"].value = "fixture-only new passphrase";
    return h.elements["auth-form"].listeners.get("submit")({ preventDefault() {} });
  };
  return { h, timers, route, submit };
}

async function testCredentialBodyAndStatusShareDeadline() {
  for (const setup of [false, true]) for (const phase of ["body", "status"]) {
    let release, reads = 0;
    const pending = new Promise(resolve => { release = resolve; });
    const { h, timers, route, submit } = await credentialHarness(setup,
      () => phase === "body" ? deferredJSONResponse(pending) : jsonResponse({ authenticated: true }),
      () => ++reads === 1 ? jsonResponse({ setup_required: setup, authenticated: false }) : deferredJSONResponse(pending));
    const submission = submit();
    await settleUI();
    assert.equal(timers.size, 1, "Reply and status must not renew the credential budget");
    const post = h.requests.find(request => request.path === route);
    if (phase === "status") assert.equal(h.requests.at(-1).options.signal, post.options.signal);
    [...timers.values()][0].callback();
    await submission;
    assert.equal(h.elements["auth-form"].hidden, true);
    assert.equal(h.elements["auth-submit"].disabled, false);
    assert.equal(timers.size, 0);
    const before = h.requests.length;
    release({ authenticated: true });
    await settleUI();
    assert.equal(h.requests.length, before);
    assert.equal(h.elements["dashboard-content"].hidden, true);
  }
}
await testCredentialBodyAndStatusShareDeadline();

async function testCredentialRefusalsAndReplyBounds() {
  for (const setup of [false, true]) {
    for (const code of [400, 401, 409, 429]) {
      const { h, timers, route, submit } = await credentialHarness(setup, () => jsonResponse({ error: "PRIVATE-SENTINEL" }, code));
      await submit();
      assert.equal(h.elements["auth-form"].hidden, false, `definitive ${code} must retain the sign-in form`);
      assert.equal(h.elements["auth-submit"].disabled, false);
      assert.equal(h.elements["auth-password"].value, "");
      assert.equal(timers.size, 0);
      assert.ok(!h.elements["auth-error"].textContent.includes("PRIVATE-SENTINEL"));
      assert.equal(h.requests.filter(request => request.path === route).length, 1);
      assert.equal(h.requests.filter(request => request.path === "/api/v1/auth/status").length, 1);
    }
    for (const kind of ["network", "server", "invalid-json", "oversize"]) {
      const { h, timers, submit } = await credentialHarness(setup, () => {
        if (kind === "network") throw new Error("PRIVATE-SENTINEL");
        if (kind === "server") return jsonResponse({ error: "PRIVATE-SENTINEL" }, 503);
        if (kind === "oversize") return jsonResponse({ data: "x".repeat(16384) });
        return { ok: true, status: 200, body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("PRIVATE-SENTINEL")); controller.close(); } }) };
      });
      await submit();
      assert.equal(h.elements["auth-form"].hidden, true, `uncertain ${kind} must require reconciliation`);
      assert.equal(h.elements["auth-retry"].hidden, false);
      assert.equal(timers.size, 0);
      assert.ok(!h.elements["auth-error"].textContent.includes("PRIVATE-SENTINEL"));
    }
    let reads = 0;
    const text = JSON.stringify({ authenticated: true });
    const { h, timers, submit } = await credentialHarness(setup, () => ({
      ok: true, status: 200, body: new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode(text + " ".repeat(16384 - text.length))); controller.close();
      } }), json: () => { throw new Error("unbounded JSON fallback"); },
    }), () => jsonResponse({ authenticated: ++reads > 1, setup_required: setup }));
    await submit();
    assert.equal(h.elements["dashboard-content"].hidden, false, "Exact16KiB reply remains inclusive");
    assert.equal(timers.size, 0);
  }
}
await testCredentialRefusalsAndReplyBounds();

async function testCredentialDuplicatesRetirementAndExplicitReconciliation() {
  for (const setup of [false, true]) {
    const pending = [];
    let authenticated = false;
    const { h, timers, route, submit } = await credentialHarness(setup,
      () => new Promise(resolve => { pending.push(resolve); }), () => jsonResponse({ authenticated, setup_required: setup }));
    const old = submit();
    await settleUI();
    const oldTimeout = [...timers.values()][0].callback;
    await submit();
    assert.equal(pending.length, 1, "Repeated submit event must not issue a second credential POST");
    h.context.showAuthUnavailable();
    await old;
    await h.elements["auth-retry"].listeners.get("click")();
    const current = submit();
    await settleUI();
    const signal = h.requests.filter(request => request.path === route).at(-1).options.signal;
    const count = h.requests.length;
    pending[0](jsonResponse({ authenticated: true })); oldTimeout();
    await settleUI();
    assert.equal(h.requests.length, count);
    assert.equal(h.elements["auth-submit"].disabled, true, "Retired finalizers must not unlock a new submission");
    assert.equal(signal.aborted, false);
    assert.equal(timers.size, 1);
    authenticated = true;
    pending[1](jsonResponse({ authenticated: true }));
    await current;
    assert.equal(h.elements["dashboard-content"].hidden, false);
    assert.equal(timers.size, 0);
  }
  for (const authenticated of [false, true]) {
    let after = false;
    const { h, timers, route, submit } = await credentialHarness(true, () => new Promise(() => {}),
      () => jsonResponse({ authenticated: after && authenticated, setup_required: !after }));
    const submission = submit(); await settleUI();
    [...timers.values()][0].callback(); await submission;
    after = true;
    await h.elements["auth-retry"].listeners.get("click")();
    assert.equal(h.requests.filter(request => request.path === route).length, 1, "Reconnect rereads status, never retries credentials");
    assert.equal(h.elements["dashboard-content"].hidden, !authenticated);
    if (!authenticated) assert.equal(h.elements["auth-form"].dataset.mode, "login", "Completed setup must not be offered again");
    assert.equal(timers.size, 0);
  }
  process.stdout.write("Credential submission controls passed: header/body/status deadlines, 16KiB replies, duplicate/retired events, fixed refusals and explicit status-only reconciliation.\n");
}
await testCredentialDuplicatesRetirementAndExplicitReconciliation();

async function mutationHarness(kind, reply) {
  const timers = new Map();
  let id = 0, statusReads = 0;
  const route = `/api/v1/auth/${kind}`;
  const h = await createHarness(async (path, options) => {
    if (path === "/api/v1/auth/status") {
      if (++statusReads === 1) return jsonResponse({ authenticated: true });
      return reply("status", options);
    }
    if (path === "/api/v1/auth/session") return reply("session", options);
    if (path === route) return reply("post", options);
    return snapshotResponse(path);
  }, {
    setTimeout: (callback, delay) => { const timer = ++id; timers.set(timer, { callback, delay }); return timer; },
    clearTimeout: timer => timers.delete(timer),
  });
  await settleUI();
  const submit = () => {
    if (kind !== "password") return h.context.signOut(kind === "logout-all");
    h.elements["password-current"].value = "fixture-only old passphrase";
    h.elements["password-new"].value = "fixture-only new passphrase";
    h.elements["password-confirm"].value = "fixture-only new passphrase";
    return h.elements["password-form"].listeners.get("submit")({ preventDefault() {} });
  };
  return { h, route, timers, submit };
}

function mutationReply(stage, kind) {
  return stage === "session" ? { csrf_token: "x".repeat(43) } : stage === "status" ? { authenticated: false } :
    kind === "password" ? { password_changed: true, reauthentication_required: true, all_panel_sessions_revoked: true } :
      kind === "logout-all" ? { all_panel_sessions_revoked: true } : { logged_out: true };
}

async function testAuthMutationLifetimeIncludesAllReads() {
  for (const kind of ["logout", "logout-all", "password"]) {
    for (const phase of ["session", "post", "status"]) for (const boundary of ["headers", "body"]) {
      let release;
      const pending = new Promise(resolve => { release = resolve; });
      const { h, route, timers, submit } = await mutationHarness(kind, stage =>
        stage === phase ? boundary === "headers" ? pending : deferredJSONResponse(pending) : jsonResponse(mutationReply(stage, kind)));
      let settled = false;
      const operation = submit().then(() => { settled = true; });
      await settleUI();
      assert.equal(timers.size, 1, `${kind}/${phase}/${boundary} must retain one original deadline`);
      const deadline = [...timers.values()][0];
      assert.equal(deadline.delay, 10000);
      deadline.callback();
      await settleUI();
      assert.equal(settled, true, `${kind}/${phase}/${boundary} must settle even when transport ignores abort`);
      await operation;
      for (const id of ["password-submit", "logout", "logout-all"]) assert.equal(h.elements[id].disabled, false);
      assert.equal(h.elements["dashboard-content"].hidden, true);
      assert.equal(h.elements["auth-form"].hidden, true);
      assert.equal(h.elements["auth-retry"].hidden, false);
      assert.match(h.elements["auth-error"].textContent, /could not be confirmed.*not retried/is);
      assert.equal(timers.size, 0);
      const count = h.requests.length;
      release(boundary === "headers" ? jsonResponse(mutationReply(phase, kind)) : mutationReply(phase, kind));
      await settleUI();
      assert.equal(h.requests.length, count, "Late mutation completion cannot post or reconcile status");
      assert.equal(h.elements["dashboard-content"].hidden, true);
      assert.equal(h.requests.filter(request => request.path === route).length, phase === "session" ? 0 : 1);
    }
  }
}
await testAuthMutationLifetimeIncludesAllReads();

async function testAuthMutationReplyBoundsAndConfirmation() {
  for (const kind of ["logout", "logout-all", "password"]) {
    for (const value of [null, {}, { csrf_token: 43 }, { csrf_token: "x".repeat(42) }, { csrf_token: "x".repeat(44) }]) {
      const { h, route, timers, submit } = await mutationHarness(kind, stage => jsonResponse(stage === "session" ? value : mutationReply(stage, kind)));
      await submit();
      assert.equal(timers.size, 0);
      assert.equal(h.requests.filter(request => request.path === route).length, 0, "Invalid session cannot authorize a mutation POST");
      assert.equal(h.elements["auth-retry"].hidden, false);
    }
    for (const stage of ["session", "post", "status"]) for (const failure of ["network", "http"]) {
      const { h, timers, submit } = await mutationHarness(kind, actualStage => {
        if (actualStage !== stage) return jsonResponse(mutationReply(actualStage, kind));
        if (failure === "network") throw new Error("PRIVATE-SENTINEL");
        return jsonResponse({ error: "PRIVATE-SENTINEL" }, 503);
      });
      await submit();
      assert.equal(timers.size, 0);
      assert.equal(h.elements["auth-retry"].hidden, false);
      assert.match(h.elements["auth-error"].textContent, /could not be confirmed/);
      assert.doesNotMatch(h.elements["auth-error"].textContent, /PRIVATE-SENTINEL/);
    }
    for (const stage of ["session", "post", "status"]) {
      for (const failure of ["inclusive", "oversize", "invalid-json", "invalid-utf8", "deep"]) {
        let unbounded = 0;
        const { h, timers, route, submit } = await mutationHarness(kind, actualStage => {
          if (actualStage !== stage) return jsonResponse(mutationReply(actualStage, kind));
          const text = JSON.stringify(mutationReply(stage, kind));
          let bytes = failure === "invalid-utf8" ? new Uint8Array([255]) : new TextEncoder().encode(
            failure === "invalid-json" ? "PRIVATE-SENTINEL" : failure === "deep" ? "[".repeat(17) + "null" + "]".repeat(17) :
              text + " ".repeat((failure === "inclusive" ? 16384 : 16385) - text.length));
          return { ok: true, status: 200,
            body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
            json: () => { unbounded++; throw new Error("PRIVATE-SENTINEL unbounded fallback"); } };
        });
        await submit();
        assert.equal(unbounded, 0);
        assert.equal(timers.size, 0);
        assert.equal(h.elements["auth-form"].hidden, failure !== "inclusive", `${kind}/${stage}/${failure}`);
        if (failure !== "inclusive") assert.match(h.elements["auth-error"].textContent, /could not be confirmed/);
        assert.doesNotMatch(h.elements["auth-error"].textContent, /PRIVATE-SENTINEL/);
        assert.equal(h.requests.filter(request => request.path === route).length, failure !== "inclusive" && stage === "session" ? 0 : 1);
      }
    }
    for (const value of [{}, null, { authenticated: true }, { authenticated: "false" }]) {
      const { h, submit, timers } = await mutationHarness(kind, stage => jsonResponse(stage === "status" ? value : mutationReply(stage, kind)));
      await submit();
      assert.equal(timers.size, 0);
      assert.equal(h.elements["dashboard-content"].hidden, true);
      assert.equal(h.elements["auth-retry"].hidden, false, "Successful mutation reply alone cannot confirm sign-out");
      assert.match(h.elements["auth-error"].textContent, /could not be confirmed/);
    }
    for (const value of [{}, null, { logged_out: false, all_panel_sessions_revoked: false }, { signed_out: true }]) {
      const { h, submit } = await mutationHarness(kind, stage => jsonResponse(stage === "post" ? value : mutationReply(stage, kind)));
      await submit();
      assert.equal(h.elements["auth-retry"].hidden, false, "Require current endpoint's actual confirmation flags");
      assert.equal(h.requests.filter(request => request.path === "/api/v1/auth/status").length, 1);
    }
  }
  for (const [status, error, definite] of [
    [401, "current_password_invalid", true], [422, "new_password_invalid", true], [429, "password_change_rate_limited", true],
    [401, "PRIVATE-SENTINEL", false], [422, "PRIVATE-SENTINEL", false], [429, "PRIVATE-SENTINEL", false], [503, "PRIVATE-SENTINEL", false],
  ]) {
    const { h, timers, submit } = await mutationHarness("password", stage =>
      stage === "post" ? jsonResponse({ error }, status) : jsonResponse(mutationReply(stage, "password")));
    await submit();
    assert.equal(timers.size, 0);
    assert.equal(h.elements["dashboard-content"].hidden, !definite);
    assert.doesNotMatch(h.elements["auth-error"].textContent + h.elements["password-status"].textContent, /PRIVATE-SENTINEL/);
  }
}
await testAuthMutationReplyBoundsAndConfirmation();

async function testAuthMutationRetirementAndReplacement() {
  for (const kind of ["logout", "logout-all", "password"]) for (const stage of ["session", "post", "status"]) {
    let oldRelease, newRelease, retiring = false, replacing = false;
    const oldPending = new Promise(resolve => { oldRelease = resolve; });
    const newPending = new Promise(resolve => { newRelease = resolve; });
    const { h, timers, route, submit } = await mutationHarness(kind, actualStage => {
      if (!retiring && actualStage === stage) return oldPending;
      if (retiring && !replacing && actualStage === "status") return jsonResponse({ authenticated: true });
      if (replacing && actualStage === "post") return newPending;
      return jsonResponse(mutationReply(actualStage, kind));
    });
    let settled = false;
    const old = submit().then(() => { settled = true; });
    await settleUI();
    const deadline = [...timers.values()][0].callback;
    const before = h.requests.length;
    await submit();
    await h.context.signOut(kind !== "logout-all");
    assert.equal(h.requests.length, before, "All auth mutations share one single-flight gate");
    h.context.showAuthUnavailable();
    await settleUI();
    assert.equal(settled, true, "Auth-view retirement must settle old work without waiting for its timer");
    await old;
    retiring = true;
    await h.context.updateAuthView({ refresh: false });
    replacing = true;
    const replacement = submit();
    await settleUI();
    const request = h.requests.filter(request => request.path === route).at(-1);
    const count = h.requests.length;
    oldRelease(jsonResponse(mutationReply(stage, kind))); deadline();
    await settleUI();
    assert.equal(h.requests.length, count);
    assert.equal(request.options.signal.aborted, false);
    assert.equal(timers.size, 1);
    for (const id of ["password-submit", "logout", "logout-all"]) assert.equal(h.elements[id].disabled, true, "Old finalizer cannot unlock replacement");
    newRelease(jsonResponse(mutationReply("post", kind)));
    await replacement;
    assert.equal(timers.size, 0);
    assert.equal(h.elements["auth-form"].hidden, false);
  }
  assert.ok(!authSource.includes(".json()"), "Auth UI must not fall back to unbounded Response.json");
  process.stdout.write("Auth mutation controls passed: session/POST/status headers+body deadlines=18, inclusive16KiB/refusals, endpoint confirmation, fixed errors, duplicate/retired work and replacement ownership.\n");
}
await testAuthMutationRetirementAndReplacement();

async function testDiagnosticStructureIsBoundedBeforeParsing() {
  let deep = null;
  for (let i = 0; i < 16; i++) deep = [deep];
  const value = { ...systemFixture(), extra: deep };
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/system" ? jsonResponse(value) : snapshotResponse(path));
  await settleUI();
  assert.equal(h.elements["kernel-value"].textContent, "Unavailable", "Over-depth diagnostic bodies must refuse before object construction");
  assert.equal(h.elements["array-count"].textContent, "2 arrays");
}
await testDiagnosticStructureIsBoundedBeforeParsing();

async function testDiagnosticByteReaderBoundariesAndCleanup() {
  let response = jsonResponse(systemFixture());
  const h = await createHarness(async (path) => path === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    path === "/api/v1/system" ? response : snapshotResponse(path));
  await settleUI();
  const streamResponse = (parts, { close = true, status = 200, cancel = () => {}, headers = {} } = {}) => {
    let index = 0;
    const body = new ReadableStream({
      pull(controller) { if (index < parts.length) controller.enqueue(parts[index++]); else if (close) controller.close(); },
      cancel,
    });
    return { ok: status === 200, status, body, headers,
      json: () => { throw new Error("Unbounded JSON fallback must not be used"); } };
  };
  const base = JSON.stringify(systemFixture());
  const encoded = new TextEncoder().encode(base);
  for (const [path, cap] of [["/api/v1/auth/status", 16384], ["/api/v1/system", 16384],
    ["/api/v1/storage", 65536], ["/api/v1/arrays", 524288], ["/api/v1/mounts", 4194304]]) {
    const text = base + " ".repeat(cap - encoded.length);
    const bytes = new TextEncoder().encode(text);
    response = streamResponse([bytes.subarray(0, 4093), bytes.subarray(4093)]);
    const previousFetch = h.context.fetch;
    h.context.fetch = async () => response;
    try {
      assert.equal((await h.context.fetchJSON(path)).kernel, "6.18.54", "Exact byte cap must remain inclusive");
      assert.equal(response.body.locked, false);
      let canceled = 0;
      response = streamResponse([bytes, new Uint8Array([32])], { close: false,
        headers: { get: () => "1" }, cancel: () => { canceled++; return new Promise(() => {}); } });
      await assert.rejects(h.context.fetchJSON(path), /diagnostic body unavailable/);
      assert.equal(canceled, 1, "Actual bytes, not Content-Length, must drive refusal/cancellation");
      assert.equal(response.body.locked, false, "Hung cancellation must not retain the reader lock");
    } finally { h.context.fetch = previousFetch; }
  }
  const utf8 = new TextEncoder().encode(JSON.stringify({ ...systemFixture(), extra: "x😀é" }));
  const offset = utf8.indexOf(240);
  response = streamResponse([utf8.subarray(0, offset + 1), utf8.subarray(offset + 1, offset + 3), utf8.subarray(offset + 3)]);
  assert.equal((await h.context.fetchJSON("/api/v1/system")).extra, "x😀é", "UTF-8 splits must not corrupt valid bytes");
  assert.equal(response.body.locked, false);
  const badInputs = [new Uint8Array([255]), new TextEncoder().encode("{\"PRIVATE-SENTINEL\":"), new Uint8Array(0)];
  for (const bytes of badInputs) {
    response = streamResponse([bytes]);
    await assert.rejects(h.context.fetchJSON("/api/v1/system"), /diagnostic body unavailable/);
    assert.equal(response.body.locked, false);
  }
  response = streamResponse([new Uint8Array([123])], { status: 503, close: false, cancel: () => {} });
  await assert.rejects(h.context.fetchJSON("/api/v1/system"), (failure) => failure.status === 503);
  assert.equal(response.body.locked, false);
  const before = h.requests.length;
  await assert.rejects(h.context.fetchJSON("/api/v1/not-a-diagnostic"), /diagnostic path unavailable/);
  assert.equal(h.requests.length, before, "Unknown paths must refuse before fetch");
  response = { ok: true, status: 200, json: () => systemFixture() };
  await assert.rejects(h.context.fetchJSON("/api/v1/system"), /diagnostic body unavailable/);

  let canceled = 0;
  response = streamResponse([], { close: false, cancel: () => { canceled++; return new Promise(() => {}); } });
  const controller = new AbortController();
  const waiting = h.context.fetchJSON("/api/v1/system", { signal: controller.signal });
  await settleUI();
  assert.equal(response.body.locked, true);
  controller.abort();
  await assert.rejects(waiting, (failure) => failure.name === "AbortError");
  await settleUI();
  assert.equal(canceled, 1);
  assert.equal(response.body.locked, false);

  const quoteText = JSON.stringify({ ...systemFixture(), extra: '\\"[[[{{}}]]]' });
  response = streamResponse([new TextEncoder().encode(quoteText)]);
  assert.equal((await h.context.fetchJSON("/api/v1/system")).extra, '\\"[[[{{}}]]]');
  response = streamResponse([new TextEncoder().encode(JSON.stringify({ ...systemFixture(), extra: Array.from({ length: 1024 }, () => ({})) }))]);
  await assert.rejects(h.context.fetchJSON("/api/v1/system"), /diagnostic body unavailable/);
  const largestMounts = { ...mountsFixture(), mount_count: 128,
    mounts: Array.from({ length: 128 }, () => ({ mount_point: ">".repeat(4096), filesystem: "x".repeat(64),
      device_major: 4294967295, device_minor: 4294967295, read_only: false })) };
  // Mirror encoding/json's HTML-escaping expansion on producer-bounded fields.
  const escaped = JSON.stringify(largestMounts).replaceAll(">", "\\u003e");
  assert.ok(new TextEncoder().encode(escaped).length < 4194304);
  const prior = h.context.fetch;
  response = streamResponse([new TextEncoder().encode(escaped)]);
  h.context.fetch = async () => response;
  try { assert.equal((await h.context.fetchJSON("/api/v1/mounts")).mounts.length, 128, "Maximum escaped producer envelope fits the byte budget"); }
  finally { h.context.fetch = prior; }
  const many = Array.from({ length: 16385 }, () => new Uint8Array([32]));
  const previousFetch = h.context.fetch;
  h.context.fetch = async () => streamResponse(many, { close: false });
  try { await assert.rejects(h.context.fetchJSON("/api/v1/mounts"), /diagnostic body unavailable/); }
  finally { h.context.fetch = previousFetch; }
  process.stdout.write("Diagnostic byte-reader controls passed: paths=5 inclusive-limits=true UTF8-split=true cancellation-locks=true no-fallback=true fragmentation=true.\n");
}
await testDiagnosticByteReaderBoundariesAndCleanup();

async function testServiceLoadRefusesOversizedBody() {
  let unboundedReads = 0;
  const value = { ...serviceReply(null), private_padding: "PRIVATE-SENTINEL".repeat(36000) };
  const h = await serviceHarness(() => {
    const reply = jsonResponse(value);
    reply.json = async () => { unboundedReads++; return value; };
    return reply;
  });
  await h.context.loadServicePolicy();
  assert.equal(h.elements["service-current"].hidden, true, "Oversized policy response must not publish a baseline");
  assert.equal(h.elements["service-save"].disabled, true);
  assert.equal(unboundedReads, 0, "Policy reads must not call unbounded Response.json");
  assert.equal(h.requests.filter((r) => r.path === "/api/v1/file-services/configuration").length, 1);
  assert.doesNotMatch(h.elements["service-status"].textContent, /PRIVATE-SENTINEL/);
}
await testServiceLoadRefusesOversizedBody();

function serviceConfigFixture() {
  return { format: "phantowd-file-service-config", schema_version: 1, revision: 1,
    shares: { ...savedFixture().configuration, revision: 1 },
    nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 1, volume_revision: 1, exports: [] } };
}

// Exercise the visible workflows, not a second implementation of the reader.
async function serviceBodyScenario(phase, respond) {
  const c = serviceConfigFixture();
  let active = false, replies = 0;
  const target = (value) => { replies++; return respond(value); };
  const h = await serviceHarness((options) => {
    if (options.method === "PUT") return phase === "save" && active ? target(serviceSaved(1)) : jsonResponse(serviceSaved(1));
    return phase === "load" && active ? target(serviceReply(null)) : jsonResponse(serviceReply(phase === "backup" ? c : null));
  }, () => phase === "preview" && active ? target(policyFixture()) : jsonResponse(policyFixture()),
  () => phase === "session" && active ? target({ csrf_token: "fixture-only" }) : jsonResponse({ csrf_token: "fixture-only" }),
  (path) => target(path.endsWith("/backup") ? backupFixture(c) : restoreFixture(c, 0)));
  await settleUI();
  fillPolicy(h.elements);
  if (phase !== "load") await h.context.loadServicePolicy();
  if (phase === "save") await h.context.prepareServiceAddition();
  if (phase === "restore") h.elements["service-restore-file"].files = [backupFile(JSON.stringify(backupFixture(c)))];
  const actions = { load: "loadServicePolicy", session: "prepareServiceAddition", preview: "prepareServiceAddition",
    save: "saveServiceChange", backup: "exportServiceBackup", restore: "previewServiceRestore" };
  return { ...h, run: () => { active = true; return h.context[actions[phase]](); }, replies: () => replies };
}

async function testServiceBodyByteBoundsAndOutcomes() {
  for (const [phase, limit] of [["load", 525056], ["session", 16384], ["preview", 4194304],
    ["save", 16384], ["backup", 525056], ["restore", 4194304]]) {
    for (const excess of [0, 1]) {
      let reply, canceled = 0, reads = 0;
      const h = await serviceBodyScenario(phase, (value) => {
        const raw = new TextEncoder().encode(JSON.stringify(value));
        const bytes = new Uint8Array(limit + excess).fill(32); bytes.set(raw);
        // Include a false Content-Length and a cancellation that never settles.
        reply = { ok: true, status: 200, headers: { get: () => "1" },
          json: () => { throw new Error("Unbounded response fallback"); },
          body: new ReadableStream({
            pull(controller) {
              reads++;
              if (reads === 1) controller.enqueue(bytes.subarray(0, limit));
              else if (reads === 2 && excess) controller.enqueue(bytes.subarray(limit));
              else if (!excess) controller.close();
            },
            cancel() { canceled++; return new Promise(() => {}); },
          }) };
        return reply;
      });
      await h.run();
      assert.equal(h.replies(), 1, `${phase}: no retry`);
      assert.equal(reply.body.locked, false, `${phase}: reader lock released`);
      assert.equal(canceled, excess, `${phase}: overflow requests cancellation`);
      assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, phase === "save" ? 1 : 0);
      if (!excess) {
        if (phase === "load") assert.equal(h.elements["service-current"].hidden, false);
        else if (phase === "save") assert.match(h.elements["service-status"].textContent, /confirmed saved/);
        else if (phase === "backup") assert.equal(h.document.downloads.length, 1);
        else assert.equal(h.elements["service-review"].hidden, false, `${phase}: inclusive byte limit`);
      } else {
        assert.equal(h.elements["service-save"].disabled, true);
        assert.equal(h.elements["service-review"].hidden, true);
        assert.equal(h.document.downloads.length, 0);
        if (phase === "load") assert.equal(h.elements["service-current"].hidden, true);
        if (phase === "save") {
          assert.match(h.elements["service-status"].textContent, /not confirmed.*may have committed/i);
          await h.context.saveServiceChange();
          assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1, "Overflow cannot authorize a second save");
        }
      }
    }
  }
}
await testServiceBodyByteBoundsAndOutcomes();

async function testServiceHTTPRefusalsDoNotConsumeErrorBodies() {
  for (const phase of ["load", "session", "preview", "save", "backup", "restore"]) {
    let canceled = 0;
    const h = await serviceBodyScenario(phase, () => ({ ok: false, status: 503,
      body: { cancel: () => { canceled++; return new Promise(() => {}); }, getReader: () => { throw new Error("Error body was consumed"); } },
      json: () => { throw new Error("Error JSON was consumed"); } }));
    await h.run();
    assert.equal(h.replies(), 1);
    assert.equal(canceled, 1, "HTTP error body cancellation is requested but not awaited");
    assert.equal(h.elements["service-save"].disabled, true);
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.document.downloads.length, 0);
    assert.match(h.elements["service-status"].textContent, phase === "save" ? /not confirmed/ : /unavailable, disabled or busy/);
  }
}
await testServiceHTTPRefusalsDoNotConsumeErrorBodies();

async function testServiceBodyDeadlineAndRetiredResults() {
  for (const phase of ["load", "session", "preview", "save", "backup", "restore"]) {
    for (const boundary of ["timeout", "auth-loss"]) {
      let release, reply, canceled = 0, expired, completed = false;
      const pending = new Promise((resolve) => { release = resolve; });
      const h = await serviceBodyScenario(phase, (value) => {
        reply = deferredJSONResponse(pending.then(() => value));
        reply.body.getReader = () => ({ read: () => pending.then(() => ({ done: false,
          value: new TextEncoder().encode(JSON.stringify(value)) })),
        cancel: () => { canceled++; return new Promise(() => {}); }, releaseLock: () => {} });
        return reply;
      });
      h.context.setTimeout = (callback, delay) => { assert.equal(delay, 10000); expired = callback; return 1; };
      h.context.clearTimeout = () => {};
      const operation = h.run().then(() => { completed = true; });
      await settleUI();
      if (boundary === "timeout") expired(); else h.context.showAuthUnavailable();
      await settleUI();
      assert.equal(completed, true, `${phase}: canceled body must release UI without waiting for the peer`);
      await operation;
      assert.equal(canceled, 1);
      assert.equal(h.replies(), 1);
      assert.equal(h.elements["service-save"].disabled, true);
      assert.equal(h.elements["service-review"].hidden, true);
      assert.equal(h.document.downloads.length, 0);
      if (phase === "save" && boundary === "timeout") assert.match(h.elements["service-status"].textContent, /not confirmed.*may have committed/i);
      const text = h.elements["service-status"].textContent;
      const count = h.requests.length;
      release(); await settleUI();
      assert.equal(h.elements["service-status"].textContent, text, "Late body cannot confirm a canceled operation");
      assert.equal(h.requests.length, count);
      assert.equal(h.document.downloads.length, 0);
    }
  }
}
await testServiceBodyDeadlineAndRetiredResults();

async function testService401RecheckCannotOverwriteReplacementSession() {
  let delayStatus = false, refuse = false, releaseStatus;
  const pending = new Promise((resolve) => { releaseStatus = resolve; });
  const h = await serviceHarness(() => refuse ? jsonResponse({}, 401) : jsonResponse(serviceReply(serviceConfigFixture())),
    undefined, undefined, undefined,
    () => delayStatus ? pending : jsonResponse({ authenticated: true }));
  await settleUI();
  refuse = delayStatus = true;
  const old = h.context.loadServicePolicy();
  await settleUI();
  assert.equal(h.elements["dashboard-content"].hidden, true, "401 must hide the retired session");
  // A real later login/status owns the view before the old status arrives.
  h.context.showAuthUnavailable();
  refuse = delayStatus = false;
  await h.context.updateAuthView({ refresh: false });
  await h.context.loadServicePolicy();
  assert.equal(h.elements["dashboard-content"].hidden, false);
  const document = h.elements["service-document"].textContent;
  releaseStatus(jsonResponse({ authenticated: false, setup_required: false }));
  await old; await settleUI();
  assert.equal(h.elements["dashboard-content"].hidden, false, "Retired401 status cannot sign out the replacement view");
  assert.equal(h.elements["service-document"].textContent, document, "Old status cannot erase replacement policy");
  assert.equal(h.elements["auth-panel"].hidden, true);
}
await testService401RecheckCannotOverwriteReplacementSession();

async function testService401RecheckKeepsOriginalDeadline() {
  for (const boundary of ["headers", "body"]) {
    let delayed = false, release, settled = false, nextTimer = 0;
    const pending = new Promise((resolve) => { release = resolve; });
    const timers = new Map();
    const h = await serviceHarness(() => jsonResponse({}, 401), undefined, undefined, undefined,
      () => !delayed ? jsonResponse({ authenticated: true }) : boundary === "headers" ? pending : deferredJSONResponse(pending));
    await settleUI();
    h.context.setTimeout = (callback, delay) => { assert.equal(delay, 10000); timers.set(++nextTimer, callback); return nextTimer; };
    h.context.clearTimeout = (id) => timers.delete(id);
    delayed = true;
    const operation = h.context.loadServicePolicy().then(() => { settled = true; });
    await settleUI();
    assert.equal(timers.size, 1, "401 status must use the original timer, not renew its budget");
    [...timers.values()][0]();
    await settleUI();
    assert.equal(settled, true, `401/${boundary} must settle on original deadline`);
    await operation;
    assert.equal(timers.size, 0);
    assert.equal(h.elements["service-load"].disabled, false);
    assert.equal(h.elements["dashboard-content"].hidden, true);
    assert.equal(h.elements["auth-retry"].hidden, false);
    const requests = h.requests.length;
    release(boundary === "headers" ? jsonResponse({ authenticated: true }) : { authenticated: true });
    await settleUI();
    assert.equal(h.elements["dashboard-content"].hidden, true, "Late401 status cannot restore the dashboard");
    assert.equal(h.requests.length, requests, "Auth status timeout cannot retry or collect diagnostics");
  }
}
await testService401RecheckKeepsOriginalDeadline();

async function testServiceHeaderDeadlineAndRetiredResults() {
  for (const phase of ["load", "session", "preview", "save", "backup", "restore"]) {
    for (const boundary of ["timeout", "auth-loss"]) {
      let release, expire, completed = false, canceled = 0;
      // Deliberately non-cooperative headers: cancellation must settle the
      // visible workflow, not wait for the fetch implementation to reject.
      const pending = new Promise((resolve) => { release = resolve; });
      const h = await serviceBodyScenario(phase, (value) => pending.then(() => {
        const reply = jsonResponse(value);
        reply.body.cancel = () => { canceled++; return new Promise(() => {}); };
        return reply;
      }));
      h.context.setTimeout = (callback, delay) => { assert.equal(delay, 10000); expire = callback; return 1; };
      h.context.clearTimeout = () => {};
      const operation = h.run().then(() => { completed = true; });
      await settleUI();
      const before = h.requests.length;
      await h.run();
      assert.equal(h.requests.length, before, "Active header wait must remain single-flight");
      if (boundary === "timeout") expire(); else h.context.showAuthUnavailable();
      await settleUI();
      assert.equal(completed, true, `${phase}/${boundary}: pending headers must not retain the UI operation`);
      await operation;
      assert.equal(h.elements["service-load"].disabled, false);
      assert.equal(h.elements["service-save"].disabled, true);
      assert.equal(h.elements["service-review"].hidden, true);
      assert.equal(h.document.downloads.length, 0);
      if (phase === "save" && boundary === "timeout") assert.match(h.elements["service-status"].textContent, /not confirmed.*may have committed/i);
      const status = h.elements["service-status"].textContent;
      const requests = h.requests.length;
      release(); await settleUI();
      assert.equal(canceled, 1, "Late headers must cancel the body without awaiting cancellation");
      assert.equal(h.elements["service-status"].textContent, status, "Late headers cannot republish retired state");
      assert.equal(h.requests.length, requests, "Late headers cannot send another preview/save or retry");
      assert.equal(h.document.downloads.length, 0);
    }
  }
}
await testServiceHeaderDeadlineAndRetiredResults();

async function testServiceRetiredHeadersCannotUnlockReplacement() {
  let releaseOld, releaseNew, calls = 0, nextTimer = 0;
  const pendingOld = new Promise((resolve) => { releaseOld = resolve; });
  const pendingNew = new Promise((resolve) => { releaseNew = resolve; });
  const timers = new Map();
  const h = await serviceBodyScenario("load", (value) => (++calls === 1 ? pendingOld : pendingNew).then(() => jsonResponse(value)));
  h.context.setTimeout = (callback) => { timers.set(++nextTimer, callback); return nextTimer; };
  h.context.clearTimeout = (id) => timers.delete(id);
  const old = h.run();
  await settleUI();
  const oldDeadline = [...timers.values()][0]; oldDeadline();
  await old;
  const replacement = h.run();
  await settleUI();
  assert.equal(h.elements["service-load"].disabled, true);
  assert.equal(timers.size, 1);
  const status = h.elements["service-status"].textContent;
  releaseOld(); await settleUI(); oldDeadline(); await settleUI();
  assert.equal(h.elements["service-load"].disabled, true, "Old finalizer cannot release replacement's gate");
  assert.equal(timers.size, 1, "Old finalizer cannot clear replacement's timer");
  assert.equal(h.elements["service-status"].textContent, status);
  releaseNew(); await replacement;
  assert.equal(timers.size, 0);
  assert.equal(h.elements["service-load"].disabled, false);
  assert.equal(h.elements["service-current"].hidden, false);
}
await testServiceRetiredHeadersCannotUnlockReplacement();
process.stdout.write("Service operation ownership controls passed: header-settlement=12 auth401-original-budget=2 retired401=true replacement-gate=true no-retry=true.\n");

async function testServiceDeadlineAtCompletedBodyHandoff() {
  for (const phase of ["load", "session", "preview", "save", "backup", "restore"]) {
    let expire;
    const h = await serviceBodyScenario(phase, (value) => {
      let sent = false;
      return { ok: true, status: 200, body: { getReader: () => ({
        read: async () => sent ? { done: true } : (sent = true, { done: false, value: new TextEncoder().encode(JSON.stringify(value)) }),
        cancel: async () => {},
        // Deterministic cancellation at the completed-reader/consumer seam.
        releaseLock: () => expire(),
      }) } };
    });
    h.context.setTimeout = (callback) => { expire = callback; return 1; };
    h.context.clearTimeout = () => {};
    await h.run();
    if (phase === "load") assert.equal(h.elements["service-current"].hidden, true, "Deadline at the body handoff cannot publish current policy");
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.elements["service-save"].disabled, true);
    assert.equal(h.document.downloads.length, 0);
    assert.match(h.elements["service-status"].textContent, phase === "save" ? /not confirmed/ : /timed out/);
    assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, phase === "save" ? 1 : 0);
    if (phase === "session") assert.equal(h.requests.filter((r) => r.path.endsWith("/preview")).length, 0);
  }
}
await testServiceDeadlineAtCompletedBodyHandoff();

async function testServiceBodiesKeepPolicySizedStructureAndRefuseMalformedData() {
  const c = serviceConfigFixture();
  c.shares.users = Array.from({ length: 128 }, (_, i) => ({ id: `user-${i}`, name: `user${i}` }));
  c.shares.shares = Array.from({ length: 16 }, (_, i) => ({ id: `share-${i}`, name: `Share ${i}`, volume_id: "media", relative_path: `folder-${i}`,
    grants: c.shares.users.map((u) => ({ user_id: u.id, access: "ro" })) }));
  const h = await serviceHarness(() => jsonResponse(serviceReply(c)));
  await h.context.loadServicePolicy();
  assert.equal(h.elements["service-current"].hidden, false, "More than1024 legitimate policy containers must remain loadable");
  assert.match(h.elements["service-summary"].textContent, /16 SMB/);
  for (const bytes of [new Uint8Array([255]), new TextEncoder().encode('{"PRIVATE-SENTINEL":'),
    new TextEncoder().encode(JSON.stringify({ ...serviceReply(null), extra: Array.from({ length: 32768 }, () => ({})) })),
    new TextEncoder().encode(JSON.stringify({ ...serviceReply(null), extra: [[[[[[[[[[[[[[[[null]]]]]]]]]]]]]]]] }))]) {
    const broken = await serviceBodyScenario("load", () => new Response(bytes));
    await broken.run();
    assert.equal(broken.elements["service-current"].hidden, true);
    assert.doesNotMatch(broken.elements["service-status"].textContent, /PRIVATE-SENTINEL/);
  }
  process.stdout.write("Service response controls passed: routes=6 inclusive/excess=true deadlines/auth-retirement=12 uncertain-save=true policy-containers=true.\n");
}
await testServiceBodiesKeepPolicySizedStructureAndRefuseMalformedData();

async function testServiceSessionBodyOverflowCannotSendPreview() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)),
    () => jsonResponse(policyFixture()),
    () => new Response(JSON.stringify({ csrf_token: "fixture-only" }) + " ".repeat(16385)));
  await h.context.loadServicePolicy();
  fillPolicy(h.elements);
  await h.context.prepareServiceAddition();
  assert.equal(h.requests.filter((r) => r.path === "/api/v1/file-services/preview").length, 0,
    "An oversized session body must refuse before a preview request");
  assert.equal(h.elements["service-save"].disabled, true);
  assert.equal(h.elements["service-review"].hidden, true);
}
await testServiceSessionBodyOverflowCannotSendPreview();
async function testServiceOversizedSaveReplyStaysUnconfirmedUntilReconcile() {
  let saved = null;
  const h = await serviceHarness((options) => {
    if (options.method === "PUT") {
      saved = JSON.parse(options.body);
      return new Response(JSON.stringify(serviceSaved(saved.revision)) + " ".repeat(16385));
    }
    return jsonResponse(serviceReply(saved));
  });
  await h.context.loadServicePolicy(); fillPolicy(h.elements);
  await h.context.prepareServiceAddition(); await h.context.saveServiceChange();
  assert.match(h.elements["service-status"].textContent, /not confirmed.*may have committed/,
    "A valid but oversized reply cannot confirm a possibly committed save");
  assert.equal(h.elements["service-save"].disabled, true);
  await h.context.saveServiceChange();
  assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
  await h.context.loadServicePolicy();
  assert.match(h.elements["service-status"].textContent, /attempted configuration.*confirmed saved/);
}
await testServiceOversizedSaveReplyStaysUnconfirmedUntilReconcile();
async function testServiceOversizedConfigurationIsNotPublished() {
  const h = await serviceHarness(() => new Response(JSON.stringify(serviceReply(null)) + " ".repeat(1024 * 1024)));
  await h.context.loadServicePolicy();
  assert.equal(h.elements["service-current"].hidden, true,
    "An oversized policy frame must not publish even an otherwise valid empty baseline");
  assert.equal(h.elements["service-prepare"].disabled, true);
  assert.equal(h.elements["service-save"].disabled, true);
}
await testServiceOversizedConfigurationIsNotPublished();
async function testServiceOversizedPreviewCannotEnableSave() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)),
    () => new Response(JSON.stringify(policyFixture()) + " ".repeat(4 * 1024 * 1024)));
  await h.context.loadServicePolicy(); fillPolicy(h.elements);
  await h.context.prepareServiceAddition();
  assert.equal(h.elements["service-save"].disabled, true,
    "A preview with an oversized frame must never admit Save");
  assert.equal(h.elements["service-review"].hidden, true);
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
}
await testServiceOversizedPreviewCannotEnableSave();
async function testAdministrativeBodyRefusalRequestsCleanupAndNeverFallsBack() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)));
  const route = "/api/v1/auth/session";
  let canceled = 0, fallback = 0;
  const response = { ok: true, status: 200,
    body: new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(16385)); },
      cancel() { canceled++; return new Promise(() => {}); },
    }), json: () => { fallback++; return { csrf_token: "fixture-only" }; } };
  await assert.rejects(h.context.readAdministrativeJSON(response, route), /administrative body unavailable/);
  assert.equal(canceled, 1); assert.equal(fallback, 0); assert.equal(response.body.locked, false);
  const controller = new AbortController();
  let settled = false;
  const pendingBody = new ReadableStream({ cancel() { settled = true; return new Promise(() => {}); } });
  const waiting = h.context.readAdministrativeJSON({ ok: true, body: pendingBody }, route, controller.signal);
  await settleUI(); controller.abort();
  await assert.rejects(waiting, (failure) => failure.name === "AbortError");
  assert.equal(settled, true); assert.equal(pendingBody.locked, false);
}
await testAdministrativeBodyRefusalRequestsCleanupAndNeverFallsBack();
async function testOversizedSessionBodyCannotDispatchSignOut() {
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return new Response(JSON.stringify({ csrf_token: "x".repeat(43) }) + " ".repeat(16385));
    if (path === "/api/v1/auth/logout") return jsonResponse({ signed_out: true });
    return snapshotResponse(path);
  });
  await settleUI();
  await h.elements.logout.listeners.get("click")();
  assert.equal(h.requests.filter((r) => r.options?.method === "POST").length, 0,
    "An oversized session must refuse before sign-out dispatch");
  assert.equal(h.elements["dashboard-content"].hidden, true);
}
await testOversizedSessionBodyCannotDispatchSignOut();
async function testOversizedPasswordReceiptCannotConfirmCredentialChange() {
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/auth/password") return new Response(JSON.stringify({
      password_changed: true, reauthentication_required: true, all_panel_sessions_revoked: true,
    }) + " ".repeat(16385));
    return snapshotResponse(path);
  });
  await settleUI();
  h.elements["password-current"].value = "old public test passphrase";
  h.elements["password-new"].value = "new public test passphrase";
  h.elements["password-confirm"].value = h.elements["password-new"].value;
  await h.elements["password-form"].listeners.get("submit")({ preventDefault() {} });
  assert.match(h.elements["auth-error"].textContent, /outcome could not be confirmed/,
    "An oversized password receipt must remain an unknown outcome, not a success");
  assert.equal(h.requests.filter((r) => r.path === "/api/v1/auth/password").length, 1);
  assert.equal(h.elements["dashboard-content"].hidden, true);
  assert.equal(h.elements["password-current"].value, "");
}
await testOversizedPasswordReceiptCannotConfirmCredentialChange();
async function testAdministrativeUnknownRouteNeverAcquiresReader() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)));
  let acquired = 0;
  const response = { ok: true, body: { getReader() {
    acquired++; return { read: async () => ({ done: true }), cancel: async () => {}, releaseLock() {} };
  } } };
  await assert.rejects(h.context.readAdministrativeJSON(response, "toString"), /administrative path unavailable/);
  assert.equal(acquired, 0, "Inherited object names are not declared response profiles");
}
await testAdministrativeUnknownRouteNeverAcquiresReader();
async function testLargeStructuredPolicyStillLoadsThroughBoundedReader() {
  let configuration = null;
  const h = await serviceHarness(() => jsonResponse(serviceReply(configuration)));
  fillPolicy(h.elements);
  const base = h.context.buildServiceAddition(null, h.context.buildPolicyProposal());
  const uuid = (n) => `11111111-2222-4333-8444-${n.toString(16).padStart(12, "0")}`;
  const users = Array.from({ length: 64 }, (_, i) => ({ id: `reader-${i}`, name: `reader${i}` }));
  configuration = structuredClone(base);
  configuration.shares.users = users;
  configuration.shares.shares = Array.from({ length: 8 }, (_, i) => ({ ...base.shares.shares[0],
    id: `share-${i}`, name: `Share${i}`, relative_path: `smb${i}`,
    grants: users.map((user) => ({ user_id: user.id, access: "ro" })) }));
  configuration.nfs.exports = Array.from({ length: 32 }, (_, i) => ({ ...base.nfs.exports[0],
    id: uuid(2000 + i), relative_path: `nfs${i}`,
    clients: Array.from({ length: 64 }, (_, j) => ({ ...base.nfs.exports[0].clients[0], network: `192.0.2.${j}/32` })) }));
  assert.ok(new TextEncoder().encode(JSON.stringify(configuration.shares)).length <= 262144);
  assert.ok(new TextEncoder().encode(JSON.stringify(configuration.nfs)).length <= 262144);
  await h.context.loadServicePolicy();
  assert.equal(h.elements["service-current"].hidden, false,
    "A producer-bounded policy with over 1024 containers must remain usable");
  assert.match(h.elements["service-summary"].textContent, /8 SMB share.*32 NFS export/);
}
await testLargeStructuredPolicyStillLoadsThroughBoundedReader();
async function testServicePendingSessionBodyTimesOutWithoutSendingPreview() {
  const timers = new Map(); let next = 0, canceled = 0;
  const body = new ReadableStream({ cancel() { canceled++; return new Promise(() => {}); } });
  const h = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/file-services/configuration") return jsonResponse(serviceReply(null));
    if (path === "/api/v1/auth/session") return { ok: true, status: 200, body };
    if (path === "/api/v1/file-services/preview") return jsonResponse(policyFixture());
    return snapshotResponse(path);
  }, { setTimeout(callback, delay) { const id = ++next; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); } });
  await settleUI(); await h.context.loadServicePolicy(); fillPolicy(h.elements);
  const operation = h.context.prepareServiceAddition(); await settleUI();
  const pending = [...timers.values()];
  assert.equal(pending.length, 1); assert.equal(pending[0].delay, 10000);
  pending[0].callback(); await operation;
  assert.match(h.elements["service-status"].textContent, /timed out.*No save was sent/);
  assert.equal(h.requests.filter((r) => r.path === "/api/v1/file-services/preview").length, 0);
  assert.equal(canceled, 1); assert.equal(body.locked, false); assert.equal(timers.size, 0);
}
await testServicePendingSessionBodyTimesOutWithoutSendingPreview();
async function testAdministrativeInclusiveByteCapsAndUTF8Refusals() {
  const h = await serviceHarness(() => jsonResponse(serviceReply(null)));
  const base = '{"value":"bounded"}';
  for (const [path, cap, method] of [
    ["/api/v1/auth/session", 16384, "GET"], ["/api/v1/auth/password", 16384, "POST"],
    ["/api/v1/storage/gpt-observation", 65536, "POST"],
    ["/api/v1/shares/configuration", 524288, "GET"],
    ["/api/v1/file-services/configuration", 1048576, "GET"],
    ["/api/v1/file-services/configuration", 16384, "PUT"],
    ["/api/v1/file-services/backup", 1048576, "GET"],
    ["/api/v1/file-services/preview", 4194304, "POST"],
    ["/api/v1/file-services/restore-preview", 4194304, "POST"],
  ]) {
    const bytes = new TextEncoder().encode(base + " ".repeat(cap - base.length));
    const response = new Response(bytes);
    assert.equal((await h.context.readAdministrativeJSON(response, path, undefined, method)).value, "bounded");
    assert.equal(response.body.locked, false);
    const excess = new Response(new Uint8Array(cap + 1));
    await assert.rejects(h.context.readAdministrativeJSON(excess, path, undefined, method), /administrative body unavailable/);
    assert.equal(excess.body.locked, false);
  }
  for (const path of ["/api/v1/auth/session", "/api/v1/file-services/preview"]) {
    await assert.rejects(h.context.readAdministrativeJSON(new Response(new Uint8Array([255])), path), /administrative body unavailable/);
    await assert.rejects(h.context.readAdministrativeJSON({ ok: true, json: () => ({ value: "forbidden fallback" }) }, path), /administrative body unavailable/);
  }
  process.stdout.write("Administrative response controls passed: routes=8 method-bound-save=true inclusive-caps=true unknown-outcomes=true native-stream-cleanup=true no-fallback=true.\n");
}
await testAdministrativeInclusiveByteCapsAndUTF8Refusals();
await testISCSIPanel(createHarness, jsonResponse, snapshotResponse);
await testNetworkPanel(createHarness, jsonResponse, snapshotResponse);
process.stdout.write("Dashboard UI interaction smoke tests passed (DOM fixture; no visual browser coverage).\n");
