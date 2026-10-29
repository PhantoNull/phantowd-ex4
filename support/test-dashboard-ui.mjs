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

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = await readFile(join(repoRoot, "src/phantowd-api/ui/app.js"), "utf8");
const serviceSource = await readFile(join(repoRoot, "src/phantowd-api/ui/service-policy.js"), "utf8");
const iscsiSource = await readFile(join(repoRoot, "src/phantowd-api/ui/iscsi-preview.js"), "utf8");
const supportSource = await readFile(join(repoRoot, "src/phantowd-api/ui/support-bundle.js"), "utf8");
const markup = await readFile(join(repoRoot, "src/phantowd-api/ui/index.html"), "utf8");
const styles = await readFile(join(repoRoot, "src/phantowd-api/ui/app.css"), "utf8");
const markupIDs = [...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
assert.equal(new Set(markupIDs).size, markupIDs.length, "duplicate HTML IDs");
for (const match of (source + serviceSource + iscsiSource).matchAll(/(?:byId|setText)\("([^"]+)"/g)) {
  assert.ok(markupIDs.includes(match[1]), `script references missing HTML ID ${match[1]}`);
}
assert.match(markup, /id="policy-nfs-fields"[^>]*hidden disabled/);
assert.match(markup, /id="policy-form"[^>]*autocomplete="off"/);
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
    ...["form", "document", "submit", "clear", "result", "status", "review-save", "load"].map((id) => `iscsi-${id}`),
    ...["add", "fields", "action", "lun-number", "name", "volume", "path", "capacity", "block-size", "allocation", "access", "initiator", "auth", "chap-user", "secret-ref", "target-user", "target-secret-ref"].map((id) => `iscsi-draft-${id}`),
    ...["submit", "fields", "mode", "target-id", "name", "state", "lun-id", "initiator", "access"].map((id) => `iscsi-edit-${id}`),
    ...["load", "backup", "status", "result", "revision", "counts", "restore-file", "restore-preview", "restore-save", "restore-review", "restore-diff", "restore-status"].map((id) => `nas-${id}`),
    "main-content", "page-title", "skip-to-content",
    "auth-panel", "auth-title", "auth-description", "auth-form", "auth-username",
    "auth-password", "auth-submit", "auth-retry", "auth-error", "dashboard-content",
    "logout", "logout-all", "refresh", "refresh-label", "snapshot-status", "error-banner",
    ...["panel", "form", "current", "new", "confirm", "submit", "status"].map((id) => `password-${id}`),
    "service-status-dot", "build-label", "kernel-value", "runtime-value", "target-value",
    "memory-value", "memory-detail", "memory-meter", "firmware-value", "firmware-detail",
    "profile-notice-title", "profile-notice-copy", "profile-notice-mark",
    "observed-at", "device-count", "device-list", "array-count", "array-list", "mount-count", "mount-list",
    "gpt-observe", "gpt-observation-status",
    "support-panel", "support-help", "support-download", "support-status",
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
  elements["iscsi-result"].hidden = true;
  elements["iscsi-review-save"].disabled = true;
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
  const context = createContext({
    document,
    fetch,
    Intl,
    Date,
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
  });
  new Script(serviceSource).runInContext(context);
  new Script(supportSource).runInContext(context);
  new Script(iscsiSource).runInContext(context);
  new Script(source).runInContext(context);
  await new Promise((resolve) => setImmediate(resolve));
  return { context, elements, requests, document };
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
        return jsonResponse({ signed_out: true });
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
      if (path === "/api/v1/auth/logout" || path === "/api/v1/auth/logout-all") { ended = true; return jsonResponse({ signed_out: true }); }
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
        delayedBody ? { ok: true, status: 200, json: () => pending } : pending);
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

async function serviceHarness(stateResponse, previewResponse = () => jsonResponse(policyFixture()), sessionResponse = () => jsonResponse({ csrf_token: "fixture-only" }), backupResponse = () => { throw new Error("unexpected backup request"); }) {
  return createHarness(async (path, options) => {
    if (path === "/api/v1/file-services/configuration") return stateResponse(options);
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
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
await testSavedPolicyStatesAndSafeRendering();
await testSavedPolicyMalformedReplies();
await testSavedPolicyLateRepliesAndAuthLoss();
await testPolicyBuilderAndSafePreview();
await testPolicyFailuresAndStaleResponses();
await testReadOnlySnapshotAndSafeRendering();
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
  assert.throws(() => edit("nfs-properties", nfs, { path: "new-nfs-path" }), /new export/i);
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
  assert.equal(elements["service-target"].children.length, 5);
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
  assert.equal(elements["service-action"].value, "nfs-client-upsert", "NFS selection offers an allowed edit");
  assert.doesNotMatch(markup, /option value="nfs-properties"/);
  assert.equal(elements["policy-nfs-enabled"].value, "on");
  elements["service-member"].value = "192.0.2.11/32"; context.selectServiceMember();
  assert.equal(elements["policy-network"].value, "192.0.2.11/32");
  assert.equal(elements["policy-nfs-access"].value, "rw");
  elements["policy-nfs-access"].value = "ro";
  await context.prepareServiceEdit();
  const previewRequests = () => requests.filter(({ path }) => path === "/api/v1/file-services/preview");
  const proposed = JSON.parse(previewRequests().at(-1).options.body).nfs.exports;
  const sources = (exports) => exports.map((e) => [e.id, e.volume_id, e.relative_path]);
  assert.deepEqual(sources(proposed), sources(c.nfs.exports), "client edit preserves NFS sources");
  assert.equal(proposed[0].clients.find((rule) => rule.network === "192.0.2.11/32").access, "ro");
  assert.equal(elements["service-save"].disabled, false);
  const previewsBeforeRefusal = previewRequests().length;
  // A stale/direct invocation must discard the previous review before any request.
  elements["service-action"].value = "nfs-properties";
  await context.prepareServiceEdit();
  assert.equal(previewRequests().length, previewsBeforeRefusal);
  assert.equal(elements["service-save"].disabled, true);
  assert.match(elements["service-status"].textContent, /new export/i);
  await context.saveServiceChange();
  assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
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
  // A semantic comparison can describe a source change without admitting it.
  const changedSource = structuredClone(c);
  changedSource.nfs.exports[0].relative_path = "new-folder";
  const sourceRows = JSON.parse(JSON.stringify(context.describeServiceChanges(c, changedSource)));
  assert.deepEqual(sourceRows.map((r) => r.kind), ["NFS definition"]);
  assert.equal(JSON.stringify(c), initial, "source comparison mutated baseline");
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

function nasSummaryFixture() {
  return { schema_version: 1, scope: "stored-desired-nas-policy-summary-only", revision: 3,
    volumes: 2, users: 1, smb_shares: 4, nfs_exports: 2, iscsi_targets: 1, iscsi_backings: 2, iscsi_luns: 2,
    applied: false, activation_available: false };
}

async function testNASSummaryExplicitReadOnlyLoad() {
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true, setup_required: false });
    if (path === "/api/v1/nas-services/summary") return jsonResponse(nasSummaryFixture());
    return snapshotResponse(path);
  });
  assert.equal(h.requests.filter((r) => r.path.includes("nas-services")).length, 0);
  await h.context.loadNASPolicySummary();
  const calls = h.requests.filter((r) => r.path.includes("nas-services"));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, "GET");
  assert.equal(calls[0].options.body, undefined);
  assert.equal(calls[0].options.cache, "no-store");
  assert.equal(calls[0].options.credentials, "same-origin");
  assert.equal(h.elements["nas-result"].hidden, false);
  assert.equal(h.elements["nas-revision"].textContent, "Revision 3");
  assert.equal(h.elements["nas-counts"].children.length, 7);
  assert.equal(h.elements["nas-counts"].children[0].textContent, "Volume references: 2");
  assert.match(h.elements["nas-status"].textContent, /Saved definitions.*running/);
}
await testNASSummaryExplicitReadOnlyLoad();

async function testNASSummaryRefusalsClearPriorValues() {
  let reply = nasSummaryFixture();
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/nas-services/summary") return reply instanceof Error ? reply : jsonResponse(reply);
    return snapshotResponse(path);
  });
  for (const bad of [null, {}, { ...nasSummaryFixture(), revision: 2 ** 53 },
    { ...nasSummaryFixture(), applied: true }, { ...nasSummaryFixture(), activation_available: true },
    { ...nasSummaryFixture(), users: "1" }, { ...nasSummaryFixture(), iscsi_luns: 65 },
    { ...nasSummaryFixture(), extra: "private" }, new Error("private transport details"),
    { ...nasSummaryFixture(), extra: "x".repeat(4096) }]) {
    reply = nasSummaryFixture(); await h.context.loadNASPolicySummary();
    assert.equal(h.elements["nas-result"].hidden, false);
    reply = bad; await h.context.loadNASPolicySummary();
    assert.equal(h.elements["nas-result"].hidden, true);
    assert.equal(h.elements["nas-counts"].children.length, 0);
    assert.equal(h.elements["nas-revision"].textContent, "");
    assert.doesNotMatch(h.elements["nas-status"].textContent, /private/);
    assert.equal(h.elements["nas-load"].disabled, false);
  }
  reply = { ...nasSummaryFixture(), volumes: 0, users: 0, smb_shares: 0, nfs_exports: 0, iscsi_targets: 0, iscsi_backings: 0, iscsi_luns: 0 };
  await h.context.loadNASPolicySummary();
  assert.equal(h.elements["nas-result"].hidden, false, "valid zero counts are not unavailable");
  assert.ok(h.requests.filter((r) => r.path.includes("nas-services")).every((r) => r.options.method === "GET"));
}
await testNASSummaryRefusalsClearPriorValues();

async function testNASSummaryLateReplyCannotSurviveLogout(backup = false) {
  let release, ended = false;
  const pending = new Promise((resolve) => { release = resolve; });
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !ended, setup_required: false });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/auth/logout") { ended = true; return jsonResponse({ signed_out: true }); }
    if (path === "/api/v1/nas-services/summary" || path === "/api/v1/nas-services/backup") return pending.then(() => jsonResponse(backup ? nasBackupFixture() : nasSummaryFixture()));
    return snapshotResponse(path);
  });
  const load = () => backup ? h.context.exportNASPolicyBackup() : h.context.loadNASPolicySummary();
  const loading = load(); await settleUI();
  await load();
  assert.equal(h.requests.filter((r) => r.path.includes("nas-services")).length, 1, "duplicate clicks are serialized");
  await h.elements.logout.listeners.get("click")();
  release(); await loading; await settleUI();
  assert.equal(h.elements["dashboard-content"].hidden, true);
  assert.equal(h.elements["nas-result"].hidden, true);
  assert.equal(h.elements["nas-counts"].children.length, 0);
  assert.equal(h.document.downloads.length, 0);
}
await testNASSummaryLateReplyCannotSurviveLogout();
await testNASSummaryLateReplyCannotSurviveLogout(true);

async function testNASSummaryHTTPRefusalsAndDeadline(backup = false) {
  for (const status of [401, 404, 503]) {
    let failed = false;
    const h = await createHarness((path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !failed || status !== 401 });
      if (path === "/api/v1/nas-services/summary" || path === "/api/v1/nas-services/backup") return jsonResponse(failed ? { error: "private" } : backup ? nasBackupFixture() : nasSummaryFixture(), failed ? status : 200);
      return snapshotResponse(path);
    });
    const load = () => backup ? h.context.exportNASPolicyBackup() : h.context.loadNASPolicySummary();
    await load(); failed = true; await load();
    assert.equal(h.elements["nas-result"].hidden, true);
    assert.equal(h.elements["nas-counts"].children.length, 0);
    if (status === 401) assert.equal(h.elements["dashboard-content"].hidden, true);
    if (status === 404) assert.match(h.elements["nas-status"].textContent, /not configured/);
    assert.equal(h.document.downloads.length, backup ? 1 : 0, "HTTP errors must not create another backup");
    assert.equal(h.requests.filter((r) => r.path.includes("nas-services")).length, 2, "no retry or legacy fallback");
  }
  const timers = [];
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/nas-services/summary" || path === "/api/v1/nas-services/backup") return new Promise(() => {});
    return snapshotResponse(path);
  }, { setTimeout: (f) => (timers.push(f), timers.length), clearTimeout: () => {} });
  const loading = backup ? h.context.exportNASPolicyBackup() : h.context.loadNASPolicySummary(); await settleUI(); timers.at(-1)(); await loading;
  assert.match(h.elements["nas-status"].textContent, /timed out/);
  assert.equal(h.elements["nas-load"].disabled, false);
  assert.equal(h.elements["nas-result"].hidden, true);
}
await testNASSummaryHTTPRefusalsAndDeadline();
await testNASSummaryHTTPRefusalsAndDeadline(true);
function nasBackupFixture() {
  return { format: "phantowd-nas-policy-backup", schema_version: 1, configuration: {
    format: "phantowd-nas-service-config", schema_version: 1, revision: 4,
    file_services: { format: "phantowd-file-service-config", schema_version: 1, revision: 4,
      shares: savedFixture().configuration,
      nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 4, volume_revision: 4, exports: [] } },
    iscsi: { format: "phantowd-iscsi-policy", schema_version: 1, revision: 4, volume_revision: 4,
      backings: [{ id: "lun", volume_id: "media", relative_path: "luns/disk.img", capacity_bytes: 512, block_size: 512, allocation: "preallocated" }], targets: [] },
  } };
}

async function testNASBackupKeepsOriginalWireNumbers() {
  const raw = JSON.stringify(nasBackupFixture()).replace('"capacity_bytes":512', '"capacity_bytes":9223372036854775296') + "\n";
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/nas-services/backup") return { ok: true, status: 200,
      body: new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(raw)); c.close(); } }) };
    return snapshotResponse(path);
  });
  assert.equal(h.requests.filter((r) => r.path.endsWith("/backup")).length, 0);
  await h.context.exportNASPolicyBackup(); await settleUI();
  assert.equal(h.document.downloads.length, 1);
  assert.equal(h.document.downloads[0].filename, "phantowd-nas-services.json");
  assert.equal(await h.document.blobs[0].text(), raw, "large 64-bit LUN sizes must not pass through JSON re-encoding");
  assert.equal(h.requests.find((r) => r.path.endsWith("/backup")).options.method, "GET");
  assert.match(h.elements["nas-status"].textContent, /revision 4.*not a data or credential backup/);
}
await testNASBackupKeepsOriginalWireNumbers();

async function testNASBackupRejectsInvalidAndSupportsBoundedDensity() {
  let raw = "";
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/nas-services/backup") return { ok: true, status: 200,
      body: new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(raw)); c.close(); } }) };
    return snapshotResponse(path);
  });
  for (const change of [(b) => { b.format = "foreign"; }, (b) => { b.schema_version = 2; },
    (b) => { b.extra = true; }, (b) => { b.configuration.iscsi.revision = 5; },
    (b) => { b.configuration.file_services.shares.users = null; }, (b) => { b.configuration = null; }]) {
    const backup = nasBackupFixture(); change(backup); raw = JSON.stringify(backup);
    await h.context.exportNASPolicyBackup();
    assert.equal(h.document.downloads.length, 0);
    assert.equal(h.elements["nas-backup"].disabled, false);
  }
  raw = JSON.stringify(nasBackupFixture()) + " ".repeat(1024 * 1024);
  await h.context.exportNASPolicyBackup(); assert.equal(h.document.downloads.length, 0);
  const backup = nasBackupFixture(), shares = backup.configuration.file_services.shares;
  shares.users = Array.from({ length: 40 }, (_, n) => ({ id: `user${n}`, name: `user${n}` }));
  shares.shares = Array.from({ length: 50 }, (_, n) => ({ id: `share${n}`, name: `Share${n}`, volume_id: "media", relative_path: `books/${n}`,
    grants: shares.users.map((u) => ({ user_id: u.id, access: "ro" })) }));
  raw = JSON.stringify(backup); await h.context.exportNASPolicyBackup();
  assert.equal(h.document.downloads.length, 1, "valid producer density above1024 containers fits the dedicated backup budget");
  assert.equal(await h.document.blobs[0].text(), raw);
}
await testNASBackupRejectsInvalidAndSupportsBoundedDensity();

async function nasRestoreHarness(oldCapacity = "512", capacity = "9223372036854775296") {
  const original = nasBackupFixture().configuration;
  original.iscsi.backings[0].capacity_bytes = Number(oldCapacity);
  const raw = (revision) => {
    const c = structuredClone(original), f = c.file_services;
    c.revision = f.revision = f.shares.revision = f.nfs.revision = f.nfs.volume_revision = c.iscsi.revision = c.iscsi.volume_revision = revision;
    c.iscsi.backings[0].capacity_bytes = 512;
    return JSON.stringify(c).replace('"capacity_bytes":512', '"capacity_bytes":' + capacity);
  };
  const state = { committed: false, saveReply: "ok", mutate: () => {} };
  const h = await createHarness((path, options) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "x".repeat(43) });
    if (path === "/api/v1/nas-services/configuration" && options.method === "GET") return jsonResponse({ schema_version: 1,
      scope: "stored-desired-nas-policy-only", revision: state.committed ? 5 : 4,
      configuration: state.committed ? JSON.parse(raw(5)) : original,
      backing_capacities: { lun: state.committed ? capacity : oldCapacity }, saved: false, applied: false, activation_available: false });
    if (path === "/api/v1/nas-services/restore-preview") {
      const expected = Number(options.headers["X-PhantoWD-Expected-Revision"]);
      const reply = { schema_version: 1, scope: "nas-policy-restore-preview-only", expected_revision: expected,
        candidate_json: raw(expected + 1), backing_capacities: { lun: capacity }, matches_current: state.committed,
        saved: false, applied: false, runtime_validated: false, activation_available: false };
      state.mutate(reply); return jsonResponse(reply);
    }
    if (path === "/api/v1/nas-services/configuration" && options.method === "PUT") {
      if (state.saveReply === "conflict") return jsonResponse({}, 409);
      state.committed = true;
      return state.saveReply === "lost" ? new Error("lost reply") : state.saveReply === "invalid" ? jsonResponse({}) : jsonResponse({ schema_version: 1,
        scope: "stored-desired-nas-policy-only", revision: 5, saved: true, applied: false, activation_available: false });
    }
    return snapshotResponse(path);
  });
  const upload = '{"format":"phantowd-nas-policy-backup","schema_version":1,"configuration":' + raw(4) + '}';
  h.elements["nas-restore-file"].files = [backupFile(upload)];
  return { ...h, state, raw, upload };
}
async function testNASRestoreReviewsAndSavesExactCandidate() {
  assert.ok(markupIDs.includes("nas-restore-preview"), "Complete NAS restore controls are unavailable");
  const h = await nasRestoreHarness();
  await h.elements["nas-restore-preview"].listeners.get("click")();
  assert.equal(h.elements["nas-restore-review"].hidden, false);
  assert.ok(h.elements["nas-restore-diff"].children.some((row) => row.children[2].textContent.includes("9223372036854775296")), "Review must show exact decimal bytes");
  assert.equal(h.requests.filter((r) => r.options.method === "PUT").length, 0);
  assert.equal(h.requests.find((r) => r.path.endsWith("restore-preview")).options.body, h.upload);
  await h.elements["nas-restore-save"].listeners.get("click")();
  assert.equal(h.requests.find((r) => r.options.method === "PUT").options.body, h.raw(5), "Save must send original candidate bytes");
  assert.match(h.elements["nas-restore-status"].textContent, /confirmed saved.*not activated/i);
}
await testNASRestoreReviewsAndSavesExactCandidate();


async function testNASRestoreUncertainSaveRequiresExplicitReconciliation() {
  for (const mode of ["lost", "invalid", "conflict"]) {
    const h = await nasRestoreHarness(); h.state.saveReply = mode;
    await h.context.previewNASRestore(); await h.context.saveNASRestore();
    assert.match(h.elements["nas-restore-status"].textContent, /not confirmed.*no automatic retry/i);
    assert.equal(h.elements["nas-restore-file"].disabled, true);
    const before = h.requests.length;
    await h.context.saveNASRestore(); await h.context.loadServicePolicy();
    assert.equal(h.requests.length, before, "uncertain full save blocks legacy writes and duplicate saves");
    await h.context.previewNASRestore();
    assert.match(h.elements["nas-restore-status"].textContent, mode === "conflict" ? /definitions differ.*Nothing was retried/ : /definitions match.*does not confirm receipt.*Nothing was retried/);
    assert.equal(h.requests.filter((r) => r.options.method === "PUT").length, 1);
    assert.equal(h.elements["nas-restore-save"].disabled, true);
    assert.equal(h.elements["service-prepare"].disabled, true, "old editor drafts require reload");
  }
}
await testNASRestoreUncertainSaveRequiresExplicitReconciliation();
async function testNASRestoreRejectsInconsistentExactComparison() {
  const h = await nasRestoreHarness("9223372036854773760", "9223372036854774272");
  assert.equal(Number("9223372036854773760"), Number("9223372036854774272"), "fixture must collide as IEEE doubles");
  h.state.mutate = (reply) => { reply.matches_current = true; };
  await h.context.previewNASRestore();
  assert.match(h.elements["nas-restore-status"].textContent, /inconsistent.*comparison/i);
  assert.equal(h.elements["nas-restore-review"].hidden, true);
}
await testNASRestoreRejectsInconsistentExactComparison();


async function testNASRestorePresentationAndRefusals() {
  const h = await nasRestoreHarness("9223372036854773760", "9223372036854774272");
  await h.context.previewNASRestore();
  const backing = h.elements["nas-restore-diff"].children.find((row) => row.children[0].textContent.includes("iSCSI backing"));
  assert.match(backing.children[1].textContent, /9223372036854773760/); assert.match(backing.children[2].textContent, /9223372036854774272/);
  for (const mutate of [(r) => { delete r.backing_capacities; }, (r) => { r.backing_capacities.lun = "01"; },
    (r) => { r.candidate_json = "null"; }, (r) => { r.candidate_json = "secret-sentinel"; }, (r) => { r.candidate_json += " ".repeat(2 * 1024 * 1024); },
    (r) => { r.saved = true; }, (r) => { r.expected_revision++; }, (r) => { r.candidate_json = r.candidate_json.replace('"block_size":512', '"block_size":123'); }]) {
    const x = await nasRestoreHarness(); x.context.JSON = JSON; x.state.mutate = mutate; await x.context.previewNASRestore();
    assert.equal(x.elements["nas-restore-review"].hidden, true); assert.equal(x.elements["nas-restore-save"].disabled, true);
    assert.doesNotMatch(x.elements["nas-restore-status"].textContent, /secret-sentinel/);
    assert.equal(x.requests.filter((r) => r.options.method === "PUT").length, 0);
  }
  for (const file of [{ size: 656385 }, { size: 1, arrayBuffer: async () => new Uint8Array([255]).buffer }]) {
    const x = await nasRestoreHarness(); x.elements["nas-restore-file"].files = [file]; await x.context.previewNASRestore();
    assert.equal(x.requests.filter((r) => r.path.includes("nas-services")).length, 0);
  }
  const x = await nasRestoreHarness(); let release;
  x.elements["nas-restore-file"].files = [{ size: 2, arrayBuffer: () => new Promise((r) => { release = r; }) }];
  const pending = x.context.previewNASRestore(); await settleUI(); x.context.clearServicePolicy();
  release(new TextEncoder().encode("{}").buffer); await pending;
  assert.equal(x.requests.filter((r) => r.path.includes("nas-services")).length, 0); assert.equal(x.elements["nas-restore-review"].hidden, true);
  const target = { id: "target", name: "iqn.2026-10.example:target", state: "disabled", luns: [{ id: "disk", number: 0, backing_id: "lun", access: "rw" }],
    initiators: [{ name: "iqn.2026-10.example:client", authentication: { mode: "chap", initiator_user: "client", initiator_secret_ref: "stored-secret" }, grants: [{ lun_id: "disk", access: "ro" }] }] };
  const y = await nasRestoreHarness(); y.state.mutate = (r) => { r.candidate_json = r.candidate_json.replace('"targets":[]', '"targets":' + JSON.stringify([target])); };
  await y.context.previewNASRestore();
  for (const kind of ["iSCSI target", "iSCSI LUN", "iSCSI initiator", "iSCSI grant"]) assert.ok(y.elements["nas-restore-diff"].children.some((row) => row.children[0].textContent.includes(kind)), kind);
}
await testNASRestorePresentationAndRefusals();

const denseRestore = await nasRestoreHarness();
denseRestore.state.mutate = (r) => {
  const c = JSON.parse(r.candidate_json), shares = c.file_services.shares;
  shares.users = Array.from({ length: 64 }, (_, n) => ({ id: `user${n}`, name: `user${n}` }));
  shares.shares = Array.from({ length: 10 }, (_, n) => ({ id: `share${n}`, name: `Share${n}`, volume_id: "media", relative_path: `books/${n}`, grants: shares.users.map((u) => ({ user_id: u.id, access: "ro" })) }));
  c.iscsi.backings[0].capacity_bytes = 512;
  r.candidate_json = JSON.stringify(c).replace('"capacity_bytes":512', '"capacity_bytes":9223372036854775296');
};
await denseRestore.context.previewNASRestore();
assert.equal(denseRestore.elements["nas-restore-review"].hidden, true);
assert.equal(denseRestore.elements["nas-restore-save"].disabled, true, "large changes must refuse instead of silently truncating review");
assert.match(denseRestore.elements["nas-restore-status"].textContent, /512.*Complete review is unavailable/);


function iscsiPanelFixture() {
  const p = { format: "phantowd-desired-iscsi-preview", schema_version: 2, scope: "desired-policy-only", revision: "18446744073709551615",
    storage_validated: false, credentials_validated: false, runtime_validated: false, activation_available: false,
    smb_definitions: 1, nfs_definitions: 0, limitations: ["Desired definitions only."],
    backings: [{ id: "lun", volume_id: "media", relative_path: "luns/disk.img", capacity_bytes: "9223372036854775296", block_size: 512, allocation: "preallocated", smb_path_overlap_count: 0, nfs_path_overlap_count: 0 }],
    targets: [{ id: "target", name: "iqn.2001-04.com.example:books", desired_state: "disabled", luns: [{ id: "mapping", number: 0, backing_id: "lun", access: "rw" }],
      initiators: [{ name: "iqn.2001-04.com.example:reader", desired_authentication: "chap", grants: [{ lun_id: "mapping", access: "ro" }] }] }] };
  const c = nasBackupFixture().configuration;
  c.iscsi.targets = [{ id: "target", name: p.targets[0].name, state: "disabled", luns: p.targets[0].luns,
    initiators: [{ name: p.targets[0].initiators[0].name, authentication: { mode: "chap", initiator_user: "private-user", initiator_secret_ref: "private-ref" }, grants: p.targets[0].initiators[0].grants }] }];
  const wire = JSON.stringify(c).replace('"capacity_bytes":512', '"capacity_bytes":9223372036854775296')
    .replace(/"(revision|volume_revision)":4/g, '"$1":18446744073709551615');
  return { value: p, wire };
}
const iscsiPanelText = (element) => [element.textContent, ...element.children.map(iscsiPanelText)].join("\n");
async function testISCSIPanelExactManualReview() {
  assert.ok(markupIDs.includes("iscsi-form"), "iSCSI review controls unavailable");
  const fixture = iscsiPanelFixture();
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "A".repeat(43) });
    if (path === "/api/v1/iscsi/preview") return jsonResponse(fixture.value);
    return snapshotResponse(path);
  });
  assert.equal(h.requests.some((r) => r.path === "/api/v1/iscsi/preview"), false, "preview must be manual");
  h.elements["iscsi-document"].value = fixture.wire;
  await h.elements["iscsi-form"].listeners.get("submit")({ preventDefault() {} });
  const sent = h.requests.filter((r) => r.path === "/api/v1/iscsi/preview");
  assert.equal(sent.length, 1); assert.equal(sent[0].options.body, fixture.wire, "original uint64 bytes must not be re-encoded");
  assert.equal(sent[0].options.method, "POST"); assert.equal(sent[0].options.headers["X-PhantoWD-CSRF"], "A".repeat(43));
  assert.equal(sent[0].options.credentials, "same-origin"); assert.equal(sent[0].options.cache, "no-store");
  assert.equal(h.elements["iscsi-result"].hidden, false);
  const text = iscsiPanelText(h.elements["iscsi-result"]);
  for (const value of [fixture.value.revision, fixture.value.backings[0].capacity_bytes, "mapping", "desired disabled", "desired ro"]) assert.ok(text.includes(value));
  assert.equal(text.includes("private-ref"), false); assert.equal(text.includes("private-user"), false);
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
}
await testISCSIPanelExactManualReview();

async function testISCSIPanelInvalidRepliesClearPreviousReview() {
  const fixture = iscsiPanelFixture(); let value = fixture.value;
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "A".repeat(43) });
    if (path === "/api/v1/iscsi/preview") return jsonResponse(value);
    return snapshotResponse(path);
  });
  h.elements["iscsi-document"].value = fixture.wire;
  const submit = () => h.elements["iscsi-form"].listeners.get("submit")({ preventDefault() {} });
  for (const [name, mutate] of Object.entries({
    schema: (p) => { p.schema_version = 3; }, authority: (p) => { p.activation_available = true; },
    grant: (p) => { p.targets[0].initiators[0].grants[0].lun_id = "missing"; },
    duplicate: (p) => { p.backings.push({ ...p.backings[0] }); },
    number: (p) => { p.backings[0].capacity_bytes = 9223372036854775296; },
    oversize: (p) => { p.padding = "private".repeat(40000); },
    alignment: (p) => { p.backings[0].capacity_bytes = "513"; },
  })) {
    value = fixture.value; await submit(); assert.equal(h.elements["iscsi-result"].hidden, false);
    value = JSON.parse(JSON.stringify(fixture.value)); mutate(value); await submit();
    assert.equal(h.elements["iscsi-result"].hidden, true, `${name}: inconsistent preview must retire earlier data`);
    assert.equal(h.elements["iscsi-result"].children.length, 0);
    assert.equal(h.elements["iscsi-submit"].disabled, false);
    assert.doesNotMatch(h.elements["iscsi-status"].textContent, /private/);
  }
  value = { ...fixture.value, backings: [], targets: [] }; await submit();
  assert.equal(h.elements["iscsi-result"].hidden, false);
  assert.match(iscsiPanelText(h.elements["iscsi-result"]), /Explicit empty desired iSCSI policy/);
}
await testISCSIPanelInvalidRepliesClearPreviousReview();

async function testISCSIPanelCancellationAndLateReplies() {
  for (const phase of ["fetch", "body"]) for (const boundary of ["input", "clear", "logout", "deadline"]) {
    const fixture = iscsiPanelFixture(), timers = []; let resolve, ended = false;
    const pending = new Promise((r) => { resolve = r; });
    const h = await createHarness((path) => {
      if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: !ended });
      if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "A".repeat(43) });
      if (path === "/api/v1/auth/logout") { ended = true; return jsonResponse({ signed_out: true }); }
      if (path === "/api/v1/iscsi/preview") return phase === "fetch" ? pending : deferredJSONResponse(pending);
      return snapshotResponse(path);
    }, { setTimeout: (f) => (timers.push(f), timers.length), clearTimeout: () => {} });
    h.elements["iscsi-document"].value = fixture.wire;
    const submit = () => h.elements["iscsi-form"].listeners.get("submit")({ preventDefault() {} });
    const loading = submit(); await settleUI(); await submit();
    assert.equal(h.requests.filter((r) => r.path === "/api/v1/iscsi/preview").length, 1, "busy preview must not queue another request");
    if (boundary === "input") { h.elements["iscsi-document"].value = "changed"; h.elements["iscsi-document"].listeners.get("input")(); }
    if (boundary === "clear") h.elements["iscsi-clear"].listeners.get("click")();
    if (boundary === "logout") await h.elements.logout.listeners.get("click")();
    if (boundary === "deadline") timers.at(-1)();
    await loading;
    resolve(phase === "fetch" ? jsonResponse(fixture.value) : fixture.value); await settleUI();
    assert.equal(h.elements["iscsi-result"].hidden, true, `${phase}/${boundary}: late data reappeared`);
    assert.equal(h.elements["iscsi-result"].children.length, 0);
    assert.equal(h.elements["iscsi-submit"].disabled, false);
    if (["clear", "logout"].includes(boundary)) assert.equal(h.elements["iscsi-document"].value, "");
    if (boundary === "input") assert.equal(h.elements["iscsi-document"].value, "changed");
    if (boundary === "deadline") assert.match(h.elements["iscsi-status"].textContent, /timed out/);
  }
}
await testISCSIPanelCancellationAndLateReplies();

async function testISCSIPanelRequestRefusals() {
  const fixture = iscsiPanelFixture(); let status = 200;
  const h = await createHarness((path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "A".repeat(43) });
    if (path === "/api/v1/iscsi/preview") return jsonResponse(status === 200 ? fixture.value : { error: "private-server-detail" }, status);
    return snapshotResponse(path);
  });
  const submit = () => h.elements["iscsi-form"].listeners.get("submit")({ preventDefault() {} });
  for (const text of [" ", "é".repeat(328065)]) {
    const count = h.requests.length; h.elements["iscsi-document"].value = text; await submit();
    assert.equal(h.requests.length, count, "empty/oversized UTF-8 input must not start a request");
  }
  h.elements["iscsi-document"].value = fixture.wire;
  for (const failure of [403, 413, 422, 503, 401]) {
    status = 200; await submit(); assert.equal(h.elements["iscsi-result"].hidden, false);
    status = failure; const count = h.requests.filter((r) => r.path === "/api/v1/iscsi/preview").length; await submit();
    assert.equal(h.requests.filter((r) => r.path === "/api/v1/iscsi/preview").length, count + 1, "HTTP refusal must not retry");
    assert.equal(h.elements["iscsi-result"].hidden, true);
    assert.equal(h.elements["iscsi-result"].children.length, 0);
    assert.doesNotMatch(h.elements["iscsi-status"].textContent, /private-server-detail/);
  }
  assert.equal(h.elements["iscsi-document"].value, "", "session loss must erase private input");
  assert.equal(h.elements["dashboard-content"].hidden, true);
}
await testISCSIPanelRequestRefusals();

const iscsiDraftInput = { name: "iqn.2026-01.org.example:draft", volume: "media", path: "luns/draft.img", capacity: "8192", "block-size": "512", allocation: "sparse", access: "ro",
  initiator: "iqn.2026-01.org.example:client", auth: "chap", "chap-user": "draft-user", "secret-ref": "draft-secret", "target-user": "", "target-secret-ref": "" };
function iscsiDraftPolicy() {
  const c = JSON.parse(iscsiPanelFixture().wire.replaceAll("18446744073709551615", "4").replaceAll("9223372036854775296", "512"));
  c.iscsi.targets[0].state = "enabled";
  c.file_services.nfs.exports = [{ id: "aaaaaaaa-1111-2222-3333-444444444444", volume_id: "media", relative_path: "books",
    clients: [{ network: "198.51.100.1/32", access: "ro", squash: "all", anonymous_uid: 65534, anonymous_gid: 65534, security: "sys" }] }];
  return c;
}
function iscsiDraftProjection(c) {
  return { ...iscsiPanelFixture().value, revision: String(c.revision), smb_definitions: c.file_services.shares.shares.length, nfs_definitions: c.file_services.nfs.exports.length,
    backings: c.iscsi.backings.map((b) => ({ ...b, capacity_bytes: String(b.capacity_bytes), smb_path_overlap_count: 0, nfs_path_overlap_count: 0 })),
    targets: c.iscsi.targets.map((t) => ({ id: t.id, name: t.name, desired_state: t.state, luns: t.luns,
      initiators: t.initiators.map((p) => ({ name: p.name, desired_authentication: p.authentication.mode, grants: p.grants })) })) };
}
async function iscsiDraftHarness(reply, timing, other = snapshotResponse) {
  const h = await createHarness((path, options) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return jsonResponse({ csrf_token: "A".repeat(43) });
    if (path === "/api/v1/iscsi/preview") return reply(options);
    return other(path, options);
  }, timing);
  h.elements["iscsi-document"].value = JSON.stringify(iscsiDraftPolicy());
  for (const [key, value] of Object.entries(iscsiDraftInput)) h.elements[`iscsi-draft-${key}`].value = value;
  return h;
}
async function testISCSIDisabledTargetForm() {
  assert.ok(markupIDs.includes("iscsi-draft-add"), "guided target controls unavailable");
  for (const mutual of [false, true]) {
    const h = await iscsiDraftHarness((options) => jsonResponse(iscsiDraftProjection(JSON.parse(options.body))));
    if (mutual) for (const [key, value] of Object.entries({ auth: "mutual-chap", "target-user": "server-user", "target-secret-ref": "server-secret", access: "rw" })) h.elements[`iscsi-draft-${key}`].value = value;
    const original = h.elements["iscsi-document"].value;
    assert.equal(h.requests.some((r) => r.path === "/api/v1/iscsi/preview"), false);
    await h.elements["iscsi-draft-add"].listeners.get("click")({ preventDefault() {} });
    const posts = h.requests.filter((r) => r.path === "/api/v1/iscsi/preview");
    assert.equal(posts.length, 2); assert.equal(posts[0].options.body, original, "original text must be validated first");
    const c = JSON.parse(posts[1].options.body), fs = c.file_services, p = c.iscsi;
    for (const r of [c.revision, fs.revision, fs.shares.revision, fs.nfs.revision, fs.nfs.volume_revision, p.revision, p.volume_revision]) assert.equal(r, 5);
    const t = p.targets.pop(), b = p.backings.pop();
    assert.equal(t.state, "disabled"); assert.equal(t.luns[0].number, 0); assert.equal(t.luns[0].backing_id, b.id);
    assert.equal(t.initiators[0].authentication.mode, mutual ? "mutual-chap" : "chap");
    assert.equal(t.initiators[0].grants[0].access, mutual ? "rw" : "ro"); assert.equal(b.capacity_bytes, 8192);
    if (mutual) assert.equal(t.initiators[0].authentication.target_secret_ref, "server-secret");
    c.revision = fs.revision = fs.shares.revision = fs.nfs.revision = fs.nfs.volume_revision = p.revision = p.volume_revision = 4;
    assert.deepEqual(c, JSON.parse(original), "existing SMB/NFS/iSCSI definitions must survive unchanged");
    assert.equal(h.elements["iscsi-document"].value, posts[1].options.body);
    assert.match(h.elements["iscsi-status"].textContent, /Disabled target staged/);
    assert.equal(h.elements["iscsi-result"].hidden, false);
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
    h.elements["iscsi-draft-name"].value += "-second";
    h.elements["iscsi-draft-path"].value = "luns/second.img";
    h.elements["iscsi-draft-secret-ref"].value = "second-secret";
    if (mutual) h.elements["iscsi-draft-target-secret-ref"].value = "second-server-secret";
    await h.elements["iscsi-draft-add"].listeners.get("click")({ preventDefault() {} });
    const next = JSON.parse(h.elements["iscsi-document"].value);
    assert.equal(next.revision, 6); assert.equal(next.iscsi.targets.length, 3);
    for (const items of [next.iscsi.targets, next.iscsi.backings, next.iscsi.targets.flatMap((t) => t.luns)]) assert.equal(new Set(items.map((i) => i.id)).size, items.length);
  }
}
await testISCSIDisabledTargetForm();

async function testISCSIDraftRefusalsPreserveOriginal() {
  const submit = (h) => h.elements["iscsi-draft-add"].listeners.get("click")({ preventDefault() {} });
  for (const fields of [
    { capacity: "9007199254740992" }, { capacity: "8193" }, { capacity: "1e4" }, { capacity: "08192" }, { capacity: "0" },
    { "block-size": "1024" }, { access: "none" }, { auth: "none" }, { volume: "missing" },
    { path: "../escape.img" }, { path: "/absolute" }, { path: "a\\b" }, { path: "a//b" },
    { "secret-ref": "secret value" }, { "chap-user": "a\nPRIVATE" }, { "target-user": "unused" },
    { auth: "mutual-chap", "target-user": "server", "target-secret-ref": "draft-secret" },
  ]) {
    const h = await iscsiDraftHarness(() => { throw new Error("invalid draft must not request preview"); });
    for (const [key, value] of Object.entries(fields)) h.elements[`iscsi-draft-${key}`].value = value;
    const original = h.elements["iscsi-document"].value, count = h.requests.length;
    await submit(h); assert.equal(h.requests.length, count); assert.equal(h.elements["iscsi-document"].value, original);
    assert.equal(h.elements["iscsi-result"].hidden, true); assert.match(h.elements["iscsi-status"].textContent, /Guided draft refused/);
  }
  for (const [from, to] of [['"revision":4', '"revision":9007199254740991'], ['"capacity_bytes":512', '"capacity_bytes":9007199254740993']]) {
    const h = await iscsiDraftHarness(() => { throw new Error("unsafe numbers must not request preview"); });
    h.elements["iscsi-document"].value = h.elements["iscsi-document"].value.replace(from, to);
    const original = h.elements["iscsi-document"].value, count = h.requests.length;
    await submit(h); assert.equal(h.requests.length, count); assert.equal(h.elements["iscsi-document"].value, original);
  }
  for (const phase of ["original", "candidate", "projection"]) {
    let calls = 0;
    const h = await iscsiDraftHarness((options) => {
      calls++;
      if (phase === "original" || phase === "candidate" && calls === 2) return jsonResponse({ error: "PRIVATE" }, 422);
      return jsonResponse(iscsiDraftProjection(calls === 2 && phase === "projection" ? iscsiDraftPolicy() : JSON.parse(options.body)));
    });
    if (phase === "original") h.elements["iscsi-document"].value = h.elements["iscsi-document"].value.replace('"revision":4', '"revision":4,"revision":4');
    const original = h.elements["iscsi-document"].value;
    await submit(h); assert.equal(calls, phase === "original" ? 1 : 2);
    assert.equal(h.requests.filter((r) => r.path === "/api/v1/iscsi/preview")[0].options.body, original);
    assert.equal(h.elements["iscsi-document"].value, original); assert.equal(h.elements["iscsi-result"].hidden, true);
    assert.equal(h.elements["iscsi-draft-fields"].disabled, false); assert.doesNotMatch(h.elements["iscsi-status"].textContent, /PRIVATE/);
  }
}
await testISCSIDraftRefusalsPreserveOriginal();

async function testISCSIDraftCandidateRetirement() {
  for (const phase of ["fetch", "body"]) for (const boundary of ["input", "clear", "logout", "deadline"]) {
    let release, calls = 0; const timers = [];
    const pending = new Promise((resolve) => { release = resolve; });
    const h = await iscsiDraftHarness((options) => {
      const value = iscsiDraftProjection(JSON.parse(options.body));
      if (++calls === 2) return phase === "fetch" ? pending : deferredJSONResponse(pending);
      return jsonResponse(value);
    }, { setTimeout: (f, ms) => (timers.push({ f, ms }), timers.length), clearTimeout: () => {} });
    const original = h.elements["iscsi-document"].value, previousTimers = timers.length;
    const submit = () => h.elements["iscsi-draft-add"].listeners.get("click")({ preventDefault() {} });
    const work = submit(); await settleUI(); assert.equal(calls, 2);
    const candidate = h.requests.filter((r) => r.path === "/api/v1/iscsi/preview")[1].options.body;
    assert.equal(h.elements["iscsi-draft-fields"].disabled, true); await submit(); assert.equal(calls, 2);
    assert.equal(timers.length, previousTimers + 1); assert.equal(timers.at(-1).ms, 10000, "both validations share one deadline");
    if (boundary === "input") h.elements["iscsi-draft-name"].listeners.get("input")();
    if (boundary === "clear") h.elements["iscsi-clear"].listeners.get("click")();
    if (boundary === "logout") h.context.showAuthUnavailable();
    if (boundary === "deadline") timers.at(-1).f();
    await work;
    assert.equal(h.elements["iscsi-document"].value, ["clear", "logout"].includes(boundary) ? "" : original);
    if (["clear", "logout"].includes(boundary)) for (const key of Object.keys(iscsiDraftInput)) {
      if (!["block-size", "allocation", "access", "auth"].includes(key)) assert.equal(h.elements[`iscsi-draft-${key}`].value, "");
    }
    h.elements["iscsi-document"].value = original;
    await h.elements["iscsi-form"].listeners.get("submit")({ preventDefault() {} });
    assert.equal(h.elements["iscsi-result"].hidden, false);
    release(phase === "fetch" ? jsonResponse({}, 401) : iscsiDraftProjection(JSON.parse(candidate))); await settleUI();
    assert.equal(h.elements["iscsi-document"].value, original, `${phase}/${boundary}: retired candidate replaced current input`);
    assert.equal(h.elements["iscsi-result"].hidden, false, "retired candidate must not replace a newer review");
    assert.equal(h.elements["iscsi-draft-add"].disabled, false); assert.equal(h.elements["iscsi-draft-fields"].disabled, false);
  }
}
await testISCSIDraftCandidateRetirement();

const iscsiClick = (h, id) => h.elements[id].listeners.get("click")({ preventDefault() {} });
function iscsiPolicyRevision(c, revision) {
  const f = c.file_services;
  c.revision = f.revision = f.shares.revision = f.nfs.revision = f.nfs.volume_revision = c.iscsi.revision = c.iscsi.volume_revision = revision;
  return c;
}
async function iscsiSaveHarness(timing) {
  const state = { current: iscsiDraftPolicy(), saveReply: "ok", candidate: null, mutatePreview: () => {} };
  const capacities = (c) => Object.fromEntries(c.iscsi.backings.map((b) => [b.id, String(b.capacity_bytes)]));
  const h = await iscsiDraftHarness((options) => jsonResponse(iscsiDraftProjection(JSON.parse(options.body))), timing, (path, options) => {
    if (path === "/api/v1/nas-services/configuration" && options.method === "GET") return jsonResponse({ schema_version: 1, scope: "stored-desired-nas-policy-only",
      revision: state.current.revision, configuration: state.current, backing_capacities: capacities(state.current), saved: false, applied: false, activation_available: false });
    if (path === "/api/v1/nas-services/restore-preview") {
      const expected = Number(options.headers["X-PhantoWD-Expected-Revision"]);
      const c = iscsiPolicyRevision(JSON.parse(options.body).configuration, expected + 1);
      state.mutatePreview(c);
      state.candidate = JSON.stringify(c);
      return jsonResponse({ schema_version: 1, scope: "nas-policy-restore-preview-only", expected_revision: expected,
        candidate_json: state.candidate, backing_capacities: capacities(c), matches_current: JSON.stringify(iscsiPolicyRevision(structuredClone(c), 0)) === JSON.stringify(iscsiPolicyRevision(structuredClone(state.current), 0)),
        saved: false, applied: false, runtime_validated: false, activation_available: false });
    }
    if (path === "/api/v1/nas-services/configuration" && options.method === "PUT") {
      if (state.saveReply !== "conflict") state.current = JSON.parse(options.body);
      if (state.saveReply === "lost") throw new Error("synthetic lost reply");
      if (state.saveReply === "conflict") return jsonResponse({}, 409);
      return jsonResponse({ schema_version: 1, scope: "stored-desired-nas-policy-only", revision: state.current.revision, saved: true, applied: false, activation_available: false });
    }
    return snapshotResponse(path);
  });
  h.saved = state;
  return h;
}
async function testISCSIDraftReviewsThenExplicitlySaves() {
  assert.ok(markupIDs.includes("iscsi-review-save"), "staged iSCSI save review control unavailable");
  const h = await iscsiSaveHarness(), original = structuredClone(h.saved.current);
  assert.equal(h.elements["iscsi-review-save"].disabled, true);
  await iscsiClick(h, "iscsi-draft-add"); assert.equal(h.elements["iscsi-review-save"].disabled, false);
  const staged = h.elements["iscsi-document"].value;
  await iscsiClick(h, "iscsi-review-save");
  assert.deepEqual(h.saved.current, original, "review must not save");
  assert.equal(h.elements["nas-restore-review"].hidden, false); assert.equal(h.elements["nas-restore-save"].disabled, false);
  for (const kind of ["iSCSI target", "iSCSI LUN", "iSCSI initiator", "iSCSI grant"]) assert.ok(h.elements["nas-restore-diff"].children.some((row) => row.children[0].textContent.includes(kind)), kind);
  const review = h.requests.find((r) => r.path === "/api/v1/nas-services/restore-preview");
  assert.ok(review.options.body.includes(staged), "staged JSON must reach the strict decoder intact");
  assert.equal(review.options.headers["X-PhantoWD-Expected-Revision"], "4");
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
  await iscsiClick(h, "nas-restore-save");
  const puts = h.requests.filter((r) => r.options?.method === "PUT");
  assert.equal(puts.length, 1); assert.equal(puts[0].options.body, h.saved.candidate);
  assert.equal(puts[0].path, "/api/v1/nas-services/configuration");
  assert.equal(h.saved.current.revision, 5); assert.equal(h.saved.current.iscsi.targets.length, 2);
  assert.deepEqual(h.saved.current.file_services, iscsiPolicyRevision(original, 5).file_services);
  assert.match(h.elements["nas-restore-status"].textContent, /confirmed saved.*not activated/);
}
await testISCSIDraftReviewsThenExplicitlySaves();

async function testISCSIDraftSavePreservesItsOriginalBaseline() {
  const previous = await iscsiSaveHarness(), backup = structuredClone(previous.saved.current);
  backup.file_services.shares.shares[0].name += " prior review";
  previous.elements["nas-restore-file"].files = [backupFile(JSON.stringify({ format: "phantowd-nas-policy-backup", schema_version: 1, configuration: backup }))];
  await iscsiClick(previous, "nas-restore-preview"); assert.equal(previous.elements["nas-restore-save"].disabled, false);
  await iscsiClick(previous, "iscsi-draft-add");
  assert.equal(previous.elements["nas-restore-save"].disabled, true, "staging a new draft must retire an unrelated whole-policy review");
  assert.equal(previous.elements["nas-restore-review"].hidden, true);
  const h = await iscsiSaveHarness(); await iscsiClick(h, "iscsi-draft-add");
  h.elements["iscsi-draft-name"].value += "-second"; h.elements["iscsi-draft-name"].listeners.get("input")();
  h.elements["iscsi-draft-path"].value = "luns/second.img";
  h.elements["iscsi-draft-secret-ref"].value = "second-secret";
  await iscsiClick(h, "iscsi-draft-add");
  assert.equal(JSON.parse(h.elements["iscsi-document"].value).revision, 6);
  await iscsiClick(h, "iscsi-review-save"); await iscsiClick(h, "nas-restore-save");
  assert.equal(h.saved.current.revision, 5, "one saved revision for the whole batch"); assert.equal(h.saved.current.iscsi.targets.length, 3);
  for (const change of [
    (c) => iscsiPolicyRevision(c, 5), (c) => { c.file_services.shares.shares[0].name += " changed"; },
    (c) => { c.file_services.nfs.exports[0].clients[0].network = "203.0.113.1/32"; }, (c) => { c.iscsi.backings[0].capacity_bytes = 1024; },
  ]) {
    const x = await iscsiSaveHarness(); await iscsiClick(x, "iscsi-draft-add"); change(x.saved.current);
    const before = structuredClone(x.saved.current); await iscsiClick(x, "iscsi-review-save");
    assert.equal(x.requests.some((r) => r.path === "/api/v1/nas-services/restore-preview" || r.options?.method === "PUT"), false);
    assert.equal(x.elements["nas-restore-save"].disabled, true); assert.match(x.elements["nas-restore-status"].textContent, /changed since this draft/);
    assert.deepEqual(x.saved.current, before);
  }
  const wrong = await iscsiSaveHarness(); await iscsiClick(wrong, "iscsi-draft-add");
  wrong.saved.mutatePreview = (c) => { c.iscsi.targets.at(-1).state = "enabled"; };
  await iscsiClick(wrong, "iscsi-review-save");
  assert.equal(wrong.elements["nas-restore-save"].disabled, true); assert.match(wrong.elements["nas-restore-status"].textContent, /Unverified iSCSI/);
}
await testISCSIDraftSavePreservesItsOriginalBaseline();

async function testISCSIDraftSaveRetirementAndUncertainReplies() {
  for (const mode of ["field", "document", "clear", "session"]) {
    const h = await iscsiSaveHarness(); await iscsiClick(h, "iscsi-draft-add"); await iscsiClick(h, "iscsi-review-save");
    if (mode === "field") h.elements["iscsi-draft-name"].listeners.get("input")();
    if (mode === "document") { h.elements["iscsi-document"].value = "changed"; h.elements["iscsi-document"].listeners.get("input")(); }
    if (mode === "clear") await iscsiClick(h, "iscsi-clear");
    if (mode === "session") h.context.showAuthUnavailable();
    assert.equal(h.elements["nas-restore-save"].disabled, true); assert.equal(h.elements["nas-restore-review"].hidden, true);
    await iscsiClick(h, "nas-restore-save"); assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
  }
  for (const phase of ["review", "save"]) {
    const h = await iscsiSaveHarness(); await iscsiClick(h, "iscsi-draft-add");
    if (phase === "save") await iscsiClick(h, "iscsi-review-save");
    const fetch = h.context.fetch; let release;
    const gate = new Promise((resolve) => { release = resolve; });
    h.context.fetch = (path, options) => path === (phase === "review" ? "/api/v1/nas-services/configuration" : "/api/v1/auth/session") ? gate : fetch(path, options);
    const work = iscsiClick(h, phase === "review" ? "iscsi-review-save" : "nas-restore-save"); await settleUI();
    h.elements["iscsi-document"].value = "changed";
    if (phase === "review") h.elements["iscsi-document"].listeners.get("input")();
    release(phase === "save" ? jsonResponse({ csrf_token: "A".repeat(43) }) : jsonResponse({ schema_version: 1, scope: "stored-desired-nas-policy-only", revision: 4, configuration: h.saved.current, backing_capacities: { lun: "512" }, saved: false, applied: false, activation_available: false }));
    await work;
    assert.equal(h.elements["nas-restore-save"].disabled, true); assert.equal(h.elements["nas-restore-review"].hidden, true);
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false, "retired work must not dispatch a save");
  }
  for (const mode of ["lost", "conflict"]) {
    const h = await iscsiSaveHarness(); await iscsiClick(h, "iscsi-draft-add"); await iscsiClick(h, "iscsi-review-save");
    h.saved.saveReply = mode; await iscsiClick(h, "nas-restore-save");
    assert.match(h.elements["nas-restore-status"].textContent, /not confirmed.*no automatic retry/);
    assert.equal(h.elements["iscsi-review-save"].disabled, true); assert.equal(h.elements["service-save"].disabled, true);
    await iscsiClick(h, "nas-restore-save"); await iscsiClick(h, "iscsi-review-save");
    assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
    await iscsiClick(h, "nas-restore-preview");
    assert.match(h.elements["nas-restore-status"].textContent, mode === "lost" ? /definitions match.*does not confirm receipt/ : /definitions differ.*Nothing was retried/);
    assert.equal(h.requests.filter((r) => r.options?.method === "PUT").length, 1);
  }
}
await testISCSIDraftSaveRetirementAndUncertainReplies();

async function testISCSILoadSavedPolicyThenAdd() {
  assert.ok(markupIDs.includes("iscsi-load"), "saved iSCSI policy load control unavailable");
  const h = await iscsiSaveHarness(), original = structuredClone(h.saved.current);
  h.elements["iscsi-document"].value = "";
  await iscsiClick(h, "iscsi-load");
  assert.deepEqual(JSON.parse(h.elements["iscsi-document"].value), original);
  assert.equal(h.requests.filter((r) => r.path === "/api/v1/nas-services/configuration").length, 1);
  assert.equal(h.requests.some((r) => r.options?.method === "POST" || r.options?.method === "PUT"), false);
  assert.equal(h.elements["iscsi-review-save"].disabled, true);
  await iscsiClick(h, "iscsi-draft-add"); await iscsiClick(h, "iscsi-review-save"); await iscsiClick(h, "nas-restore-save");
  assert.equal(h.saved.current.revision, 5); assert.equal(h.saved.current.iscsi.targets.length, 2);
  assert.deepEqual(h.saved.current.file_services, iscsiPolicyRevision(original, 5).file_services);
}
await testISCSILoadSavedPolicyThenAdd();

async function testISCSILoadRefusesUnsafeNumbers() {
  const h = await iscsiSaveHarness();
  h.elements["iscsi-document"].value = "manual input stays exact";
  h.saved.current.iscsi.backings[0].capacity_bytes = 9007199254740992;
  await iscsiClick(h, "iscsi-load");
  assert.equal(h.elements["iscsi-document"].value, "manual input stays exact", "unsafe saved capacity must not be rounded into a draft");
  assert.match(h.elements["iscsi-status"].textContent, /exact.*integers|safe.*integers/);
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
}
await testISCSILoadRefusesUnsafeNumbers();

async function testISCSILoadControlTracksPreviewLifetime() {
  const h = await iscsiSaveHarness(), originalFetch = h.context.fetch; let release;
  const pending = new Promise((resolve) => { release = resolve; });
  h.context.fetch = (path, options) => path === "/api/v1/iscsi/preview" ? pending : originalFetch(path, options);
  const work = iscsiClick(h, "iscsi-draft-add"); await settleUI();
  assert.equal(h.elements["iscsi-load"].disabled, true, "loading must be unavailable during a preview");
  await iscsiClick(h, "iscsi-clear"); await work;
  assert.equal(h.elements["iscsi-load"].disabled, false, "clear must restore loading after canceled preview");
  release(jsonResponse(iscsiDraftProjection(h.saved.current))); await settleUI();
  assert.equal(h.elements["iscsi-document"].value, "");
}
await testISCSILoadControlTracksPreviewLifetime();

function iscsiLoadedReply(c) {
  return { schema_version: 1, scope: "stored-desired-nas-policy-only", revision: c.revision, configuration: c,
    backing_capacities: Object.fromEntries(c.iscsi.backings.map((b) => [b.id, String(b.capacity_bytes)])), saved: false, applied: false, activation_available: false };
}
async function testISCSILoadRefusalsAndUnknownSave() {
  for (const kind of ["scope", "activation", "revision", "capacity", "unknown", "oversize", "unavailable", "session"]) {
    const h = await iscsiSaveHarness(), reply = iscsiLoadedReply(structuredClone(h.saved.current));
    const original = h.elements["iscsi-document"].value, fetch = h.context.fetch;
    if (kind === "scope") reply.scope = "other";
    if (kind === "activation") reply.activation_available = true;
    if (kind === "revision") reply.revision++;
    if (kind === "capacity") reply.backing_capacities.lun = "1024";
    if (kind === "unknown") reply.configuration.extra = "not silently discarded";
    if (kind === "oversize") reply.padding = "x".repeat(2 * 1024 * 1024);
    h.context.fetch = (path, options) => path === "/api/v1/nas-services/configuration" ?
      jsonResponse(reply, kind === "unavailable" ? 503 : kind === "session" ? 401 : 200) : fetch(path, options);
    await iscsiClick(h, "iscsi-load");
    assert.equal(h.elements["iscsi-document"].value, kind === "session" ? "" : original, kind);
    assert.equal(h.elements["iscsi-review-save"].disabled, true);
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
    if (kind === "session") assert.equal(h.elements["dashboard-content"].hidden, true);
  }
  const h = await iscsiSaveHarness(); await iscsiClick(h, "iscsi-draft-add"); await iscsiClick(h, "iscsi-review-save");
  h.saved.saveReply = "lost"; await iscsiClick(h, "nas-restore-save");
  const before = h.requests.length, original = h.elements["iscsi-document"].value;
  assert.equal(h.elements["iscsi-load"].disabled, true);
  await iscsiClick(h, "iscsi-load");
  assert.equal(h.requests.length, before); assert.equal(h.elements["iscsi-document"].value, original);
}
await testISCSILoadRefusalsAndUnknownSave();

async function testISCSILoadLateRepliesNeverReplaceInput() {
  for (const phase of ["fetch", "body"]) for (const boundary of ["input", "clear", "session", "deadline", "programmatic"]) {
    const timers = []; let release, loads = 0;
    const pending = new Promise((resolve) => { release = resolve; });
    const h = await iscsiSaveHarness({ setTimeout: (f) => (timers.push(f), timers.length), clearTimeout: () => {} });
    const reply = iscsiLoadedReply(h.saved.current), fetch = h.context.fetch;
    h.elements["iscsi-document"].value = "original manual input";
    h.context.fetch = (path, options) => {
      if (path !== "/api/v1/nas-services/configuration") return fetch(path, options);
      loads++; return phase === "fetch" ? pending : deferredJSONResponse(pending);
    };
    const work = iscsiClick(h, "iscsi-load"); await settleUI();
    assert.equal(h.elements["iscsi-load"].disabled, true);
    await iscsiClick(h, "iscsi-load"); assert.equal(loads, 1, "busy load must not queue another request");
    if (["input", "programmatic"].includes(boundary)) h.elements["iscsi-document"].value = "new manual input";
    if (boundary === "input") h.elements["iscsi-document"].listeners.get("input")();
    if (boundary === "clear") await iscsiClick(h, "iscsi-clear");
    if (boundary === "session") h.context.showAuthUnavailable();
    if (boundary === "deadline") timers.at(-1)();
    const late = phase === "fetch" ? jsonResponse(reply) : reply;
    if (boundary === "programmatic") release(late);
    await work;
    if (boundary !== "programmatic") release(late);
    await settleUI();
    const expected = ["clear", "session"].includes(boundary) ? "" : boundary === "deadline" ? "original manual input" : "new manual input";
    assert.equal(h.elements["iscsi-document"].value, expected, `${phase}/${boundary}`);
    assert.equal(h.elements["iscsi-result"].hidden, true); assert.equal(h.elements["iscsi-review-save"].disabled, true);
    assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
  }
}
await testISCSILoadLateRepliesNeverReplaceInput();

async function testISCSIAdditionalLUNPreservesTargetAndAuthentication() {
  assert.ok(markupIDs.includes("iscsi-draft-action") && markupIDs.includes("iscsi-draft-lun-number"), "additional LUN controls unavailable");
  const h = await iscsiDraftHarness((options) => jsonResponse(iscsiDraftProjection(JSON.parse(options.body))));
  const before = JSON.parse(h.elements["iscsi-document"].value);
  before.iscsi.targets[0].state = "disabled";
  h.elements["iscsi-document"].value = JSON.stringify(before);
  for (const [field, value] of Object.entries({ action: "lun", "lun-number": "42", name: before.iscsi.targets[0].name, initiator: before.iscsi.targets[0].initiators[0].name })) h.elements[`iscsi-draft-${field}`].value = value;
  await iscsiClick(h, "iscsi-draft-add");
  const posts = h.requests.filter((r) => r.path === "/api/v1/iscsi/preview");
  assert.equal(posts.length, 2, "original and candidate require separate validation");
  assert.equal(posts[0].options.body, JSON.stringify(before));
  const after = JSON.parse(h.elements["iscsi-document"].value), target = after.iscsi.targets[0];
  assert.equal(after.iscsi.targets.length, before.iscsi.targets.length);
  const lun = target.luns.pop(), backing = after.iscsi.backings.pop(), grant = target.initiators[0].grants.pop();
  assert.equal(lun.number, 42); assert.equal(lun.backing_id, backing.id); assert.equal(grant.lun_id, lun.id); assert.equal(grant.access, "ro");
  assert.deepEqual(iscsiPolicyRevision(after, before.revision), before, "all original definitions and authentication must remain unchanged");
  assert.equal(h.elements["iscsi-result"].hidden, false); assert.equal(h.elements["iscsi-review-save"].disabled, false);
  assert.equal(h.requests.some((r) => r.options?.method === "PUT"), false);
}
await testISCSIAdditionalLUNPreservesTargetAndAuthentication();

async function iscsiLUNHarness(reply = options => jsonResponse(iscsiDraftProjection(JSON.parse(options.body))), timing, saving = false) {
  const h = saving ? await iscsiSaveHarness(timing) : await iscsiDraftHarness(reply, timing);
  const c = JSON.parse(h.elements["iscsi-document"].value);
  c.iscsi.targets[0].state = "disabled";
  if (saving) h.saved.current = structuredClone(c);
  h.elements["iscsi-document"].value = JSON.stringify(c);
  for (const [field, value] of Object.entries({ action: "lun", "lun-number": "42", name: c.iscsi.targets[0].name, initiator: c.iscsi.targets[0].initiators[0].name })) h.elements[`iscsi-draft-${field}`].value = value;
  return h;
}
async function testISCSIAdditionalLUNBatchExplicitSave() {
  const h = await iscsiLUNHarness(undefined, undefined, true), original = structuredClone(h.saved.current);
  const peer = structuredClone(original.iscsi.targets[0].initiators[0]);
  peer.name += "-other"; peer.authentication.initiator_secret_ref = "other-peer-secret";
  if (peer.authentication.mode === "mutual-chap") peer.authentication.target_secret_ref = "other-target-secret";
  original.iscsi.targets[0].initiators.push(peer); h.saved.current = structuredClone(original);
  h.elements["iscsi-document"].value = JSON.stringify(original);
  h.elements["iscsi-draft-access"].value = "rw";
  for (const n of [42, 43]) {
    h.elements["iscsi-draft-lun-number"].value = String(n);
    h.elements["iscsi-draft-lun-number"].listeners.get("input")();
    h.elements["iscsi-draft-path"].value = `luns/additional-${n}.img`;
    await iscsiClick(h, "iscsi-draft-add");
    assert.equal(h.elements["iscsi-result"].hidden, false);
    assert.equal(h.elements["iscsi-draft-auth"].disabled, true); assert.equal(h.elements["iscsi-draft-secret-ref"].disabled, true);
  }
  assert.deepEqual(h.saved.current, original, "staging must not save");
  await iscsiClick(h, "iscsi-review-save"); assert.equal(h.elements["nas-restore-save"].disabled, false);
  assert.equal(h.requests.some(r => r.options?.method === "PUT"), false);
  await iscsiClick(h, "nas-restore-save");
  assert.equal(h.requests.filter(r => r.options?.method === "PUT").length, 1);
  const saved = structuredClone(h.saved.current), target = saved.iscsi.targets[0];
  assert.equal(saved.revision, 5); assert.equal(saved.iscsi.targets.length, original.iscsi.targets.length);
  for (const n of [43, 42]) {
    const l = target.luns.pop(), b = saved.iscsi.backings.pop(), g = target.initiators[0].grants.pop();
    assert.equal(l.number, n); assert.equal(l.access, "rw"); assert.equal(l.backing_id, b.id); assert.equal(g.lun_id, l.id); assert.equal(g.access, "rw");
  }
  assert.deepEqual(iscsiPolicyRevision(saved, 4), original, "unselected peers, authentication, SMB/NFS and all old definitions must survive");
}
await testISCSIAdditionalLUNBatchExplicitSave();

async function testISCSIAdditionalLUNRefusalsAndTargetCapacity() {
  for (const fields of [{ name: "missing" }, { initiator: "missing" }, { action: "unknown" }, { "lun-number": "" },
    ...["65536", "-1", "01", "1e2", "1.0"].map(n => ({ "lun-number": n })), { capacity: "9007199254740992" }, { volume: "missing" }, { path: "../escape" }]) {
    const h = await iscsiLUNHarness();
    for (const [field, value] of Object.entries(fields)) h.elements[`iscsi-draft-${field}`].value = value;
    const text = h.elements["iscsi-document"].value, count = h.requests.length;
    await iscsiClick(h, "iscsi-draft-add"); assert.equal(h.requests.length, count); assert.equal(h.elements["iscsi-document"].value, text);
    assert.equal(h.elements["iscsi-review-save"].disabled, true);
  }
  for (const fault of ["enabled", "removed", "duplicate", "full-luns", "full-backings", "unsafe-base"]) {
    const h = await iscsiLUNHarness(), c = JSON.parse(h.elements["iscsi-document"].value), t = c.iscsi.targets[0];
    if (fault === "enabled") t.state = "enabled";
    if (fault === "removed") c.iscsi.targets = [];
    if (fault === "duplicate") h.elements["iscsi-draft-lun-number"].value = String(t.luns[0].number);
    if (fault === "full-luns") t.luns = Array.from({ length: 16 }, (_, i) => ({ ...t.luns[0], id: `full-${i}`, number: i }));
    if (fault === "full-backings") c.iscsi.backings = Array.from({ length: 64 }, (_, i) => ({ ...c.iscsi.backings[0], id: `full-${i}` }));
    if (fault === "unsafe-base") c.iscsi.backings[0].capacity_bytes = 9007199254740992;
    h.elements["iscsi-document"].value = JSON.stringify(c);
    const text = h.elements["iscsi-document"].value, count = h.requests.length;
    await iscsiClick(h, "iscsi-draft-add"); assert.equal(h.requests.length, count, fault); assert.equal(h.elements["iscsi-document"].value, text);
  }
  const h = await iscsiLUNHarness(), c = JSON.parse(h.elements["iscsi-document"].value), seed = structuredClone(c.iscsi.targets[0]), backing = c.iscsi.backings[0];
  c.iscsi.targets = Array.from({ length: 16 }, (_, i) => ({ ...structuredClone(seed), id: `target-${i}`, name: `${seed.name}-${i}`,
    luns: [{ ...seed.luns[0], id: `lun-${i}`, backing_id: `backing-${i}` }], initiators: seed.initiators.map((p, j) => ({ ...structuredClone(p),
      authentication: { ...p.authentication, initiator_secret_ref: `in-${i}-${j}`, ...(p.authentication.mode === "mutual-chap" ? { target_secret_ref: `out-${i}-${j}` } : {}) },
      grants: [{ lun_id: `lun-${i}`, access: "ro" }] })) }));
  c.iscsi.backings = c.iscsi.targets.map((_, i) => ({ ...backing, id: `backing-${i}`, relative_path: `luns/full-target-${i}.img` }));
  h.elements["iscsi-document"].value = JSON.stringify(c); h.elements["iscsi-draft-name"].value = c.iscsi.targets[0].name;
  h.elements["iscsi-draft-lun-number"].value = "65535";
  await iscsiClick(h, "iscsi-draft-add");
  const result = JSON.parse(h.elements["iscsi-document"].value);
  assert.equal(result.iscsi.targets.length, 16); assert.equal(result.iscsi.backings.length, 17, "a free target slot is not needed for an extra LUN");
  assert.equal(result.iscsi.targets[0].luns.length, 2);
  assert.equal(result.iscsi.targets[0].luns.at(-1).number, 65535);
}
await testISCSIAdditionalLUNRefusalsAndTargetCapacity();

async function testISCSIAdditionalLUNResponseBindingAndRetirement() {
  for (const fault of ["number", "backing", "grant", "capacity", "enabled", "original-refused"]) {
    let calls = 0;
    const h = await iscsiLUNHarness(options => {
      const c = JSON.parse(options.body), value = iscsiDraftProjection(c); calls++;
      if (fault === "original-refused") return jsonResponse({}, 422);
      if (calls === 2) {
        if (fault === "number") value.targets[0].luns.at(-1).number++;
        if (fault === "backing") value.targets[0].luns.at(-1).backing_id = c.iscsi.backings[0].id;
        if (fault === "grant") value.targets[0].initiators[0].grants.pop();
        if (fault === "capacity") value.backings.at(-1).capacity_bytes = "16384";
        if (fault === "enabled") value.targets[0].desired_state = "enabled";
      }
      return jsonResponse(value);
    });
    const text = h.elements["iscsi-document"].value; await iscsiClick(h, "iscsi-draft-add");
    assert.equal(calls, fault === "original-refused" ? 1 : 2);
    assert.equal(h.elements["iscsi-document"].value, text); assert.equal(h.elements["iscsi-review-save"].disabled, true);
  }
  for (const boundary of ["action", "lun-number", "clear", "session", "deadline"]) {
    let release, candidate, calls = 0; const timers = [], pending = new Promise(resolve => { release = resolve; });
    const h = await iscsiLUNHarness(options => {
      const value = iscsiDraftProjection(JSON.parse(options.body));
      if (++calls === 2) { candidate = value; return pending; }
      return jsonResponse(value);
    }, { setTimeout: (f, ms) => (timers.push({ f, ms }), timers.length), clearTimeout() {} });
    const text = h.elements["iscsi-document"].value, work = iscsiClick(h, "iscsi-draft-add"); await settleUI();
    if (["action", "lun-number"].includes(boundary)) h.elements[`iscsi-draft-${boundary}`].listeners.get("input")();
    if (boundary === "clear") await iscsiClick(h, "iscsi-clear");
    if (boundary === "session") h.context.showAuthUnavailable();
    if (boundary === "deadline") timers.at(-1).f();
    await work; release(jsonResponse(candidate)); await settleUI();
    assert.equal(h.elements["iscsi-document"].value, ["clear", "session"].includes(boundary) ? "" : text);
    assert.equal(h.elements["iscsi-review-save"].disabled, true); assert.equal(h.elements["iscsi-result"].hidden, true);
    if (["clear", "session"].includes(boundary)) {
      assert.equal(h.elements["iscsi-draft-action"].value, "target"); assert.equal(h.elements["iscsi-draft-lun-number"].value, "0");
    }
  }
}
await testISCSIAdditionalLUNResponseBindingAndRetirement();

async function testISCSIScopedTargetStateStagesOnlySelectedDefinition() {
  assert.ok(markupIDs.includes("iscsi-edit-submit"), "scoped iSCSI edit controls unavailable");
  const h = await iscsiDraftHarness(options => jsonResponse(iscsiDraftProjection(JSON.parse(options.body))));
  const before = JSON.parse(h.elements["iscsi-document"].value), target = before.iscsi.targets[0];
  assert.equal(target.state, "enabled");
  for (const [field, value] of Object.entries({ mode: "target-state", "target-id": target.id, name: target.name, state: "disabled", "lun-id": "", initiator: "", access: "" })) h.elements[`iscsi-edit-${field}`].value = value;
  await iscsiClick(h, "iscsi-edit-submit");
  const posts = h.requests.filter(r => r.path === "/api/v1/iscsi/preview");
  assert.equal(posts.length, 2); assert.equal(posts[0].options.body, JSON.stringify(before));
  target.state = "disabled";
  assert.deepEqual(JSON.parse(h.elements["iscsi-document"].value), iscsiPolicyRevision(before, before.revision + 1));
  assert.equal(h.elements["iscsi-review-save"].disabled, false); assert.equal(h.requests.some(r => r.options?.method === "PUT"), false);
}
await testISCSIScopedTargetStateStagesOnlySelectedDefinition();

async function scopedISCSIEdit(h, c, mode, changes = {}) {
  const t = c.iscsi.targets[0];
  const fields = { mode, "target-id": t.id, name: t.name, state: "", "lun-id": t.luns[0].id, initiator: t.initiators[0].name, access: "", ...changes };
  for (const [field, value] of Object.entries(fields)) { h.elements[`iscsi-edit-${field}`].value = value; h.elements[`iscsi-edit-${field}`].listeners.get("input")(); }
  await iscsiClick(h, "iscsi-edit-submit");
}
async function testISCSIScopedAccessSequenceAndExplicitSave() {
  const h = await iscsiSaveHarness(), original = structuredClone(h.saved.current), t = original.iscsi.targets[0];
  t.initiators[0].authentication = { ...t.initiators[0].authentication, mode: "mutual-chap", target_user: "retained-user", target_secret_ref: "retained-target-ref" };
  original.iscsi.backings.push({ ...original.iscsi.backings[0], id: "other-backing", relative_path: "luns/other.img" });
  t.luns.push({ ...t.luns[0], id: "other-lun", number: 1, backing_id: "other-backing" });
  t.initiators.push({ ...structuredClone(t.initiators[0]), name: t.initiators[0].name + "-other", authentication: { mode: "chap", initiator_user: "other-user", initiator_secret_ref: "other-ref" }, grants: [{ lun_id: "other-lun", access: "rw" }] });
  h.saved.current = structuredClone(original); h.elements["iscsi-document"].value = JSON.stringify(original);
  await scopedISCSIEdit(h, original, "target-state", { state: "disabled" });
  await scopedISCSIEdit(h, original, "grant-access", { access: "rw" });
  const staged = h.elements["iscsi-document"].value, requests = h.requests.length;
  await scopedISCSIEdit(h, original, "lun-access", { access: "ro" });
  assert.equal(h.elements["iscsi-document"].value, staged); assert.equal(h.requests.length, requests, "LUN downgrade must not silently reduce rw grants");
  await scopedISCSIEdit(h, original, "grant-access", { access: "ro" });
  await scopedISCSIEdit(h, original, "lun-access", { access: "ro" });
  await scopedISCSIEdit(h, original, "target-state", { state: "enabled" });
  assert.equal(h.requests.filter(r => r.options?.method === "PUT").length, 0); assert.deepEqual(h.saved.current, original);
  await iscsiClick(h, "iscsi-review-save"); assert.equal(h.elements["nas-restore-save"].disabled, false);
  await iscsiClick(h, "nas-restore-save"); assert.equal(h.requests.filter(r => r.options?.method === "PUT").length, 1);
  const expected = structuredClone(original); expected.iscsi.targets[0].luns[0].access = "ro";
  assert.deepEqual(h.saved.current, iscsiPolicyRevision(expected, 5), "preserve authentication, other LUNs/peers/backings and all SMB/NFS definitions");
}
await testISCSIScopedAccessSequenceAndExplicitSave();

async function testISCSIScopedRefusalsAndCompleteProjection() {
  const normal = options => jsonResponse(iscsiDraftProjection(JSON.parse(options.body)));
  for (const patch of [{ mode: "" }, { mode: "unknown" }, { "target-id": "missing" }, { name: "iqn.2026-10.org.example:missing" },
    { "lun-id": "missing" }, { mode: "grant-access", initiator: "iqn.2026-10.org.example:missing", access: "rw" },
    { mode: "grant-access", access: "ro" }, { access: "rw" }, { mode: "target-state", state: "disabled" },
    { mode: "target-state", state: "missing" }, { access: "invalid" }, { "target-id": "bad\nid" }]) {
    const h = await iscsiDraftHarness(normal), c = JSON.parse(h.elements["iscsi-document"].value); c.iscsi.targets[0].state = "disabled";
    h.elements["iscsi-document"].value = JSON.stringify(c); const text = h.elements["iscsi-document"].value, count = h.requests.length;
    await scopedISCSIEdit(h, c, "lun-access", { access: "ro", ...patch });
    assert.equal(h.requests.length, count); assert.equal(h.elements["iscsi-document"].value, text); assert.equal(h.elements["iscsi-review-save"].disabled, true);
  }
  for (const fault of ["enabled", "rw-grant", "ro-lun", "unsafe"]) {
    const h = await iscsiDraftHarness(normal), c = JSON.parse(h.elements["iscsi-document"].value), t = c.iscsi.targets[0]; t.state = fault === "enabled" ? "enabled" : "disabled";
    if (fault === "rw-grant") t.initiators[0].grants[0].access = "rw";
    if (fault === "ro-lun") t.luns[0].access = "ro";
    if (fault === "unsafe") c.iscsi.backings[0].capacity_bytes = 9007199254740992;
    h.elements["iscsi-document"].value = JSON.stringify(c); const text = h.elements["iscsi-document"].value, count = h.requests.length;
    await scopedISCSIEdit(h, c, fault === "ro-lun" ? "grant-access" : "lun-access", { access: fault === "ro-lun" ? "rw" : "ro" });
    assert.equal(h.requests.length, count, fault); assert.equal(h.elements["iscsi-document"].value, text);
  }
  for (const fault of ["original-refused", "candidate-refused", "revision", "lun", "grant", "authentication", "capacity", "path", "name", "smb", "nfs"]) {
    let calls = 0;
    const h = await iscsiDraftHarness(options => {
      const value = iscsiDraftProjection(JSON.parse(options.body)); calls++;
      if (fault === "original-refused" || (calls === 2 && fault === "candidate-refused")) return jsonResponse({}, 422);
      if (calls === 2) {
        if (fault === "revision") value.revision = "6";
        if (fault === "lun") value.targets[0].luns[0].access = "ro";
        if (fault === "grant") value.targets[0].initiators[0].grants[0].access = "rw";
        if (fault === "authentication") value.targets[0].initiators[0].desired_authentication = "mutual-chap";
        if (fault === "capacity") value.backings[0].capacity_bytes = "1024";
        if (fault === "path") value.backings[0].relative_path = "luns/swapped.img";
        if (fault === "name") value.targets[0].name += "-swapped";
        if (fault === "smb") value.smb_definitions++;
        if (fault === "nfs") value.nfs_definitions++;
      }
      return jsonResponse(value);
    });
    const c = JSON.parse(h.elements["iscsi-document"].value), text = h.elements["iscsi-document"].value;
    await scopedISCSIEdit(h, c, "target-state", { state: "disabled" });
    assert.equal(calls, fault === "original-refused" ? 1 : 2); assert.equal(h.elements["iscsi-document"].value, text, fault);
    assert.equal(h.elements["iscsi-result"].hidden, true); assert.equal(h.elements["iscsi-review-save"].disabled, true);
  }
}
await testISCSIScopedRefusalsAndCompleteProjection();

async function testISCSIScopedLateRepliesAndRetirement() {
  for (const phase of ["fetch", "body"]) for (const boundary of ["field", "input", "clear", "session", "deadline", "programmatic"]) {
    let release, candidate, calls = 0; const timers = [], pending = new Promise(resolve => { release = resolve; });
    const h = await iscsiDraftHarness(options => {
      const value = iscsiDraftProjection(JSON.parse(options.body));
      if (++calls === 2) { candidate = value; return phase === "fetch" ? pending : deferredJSONResponse(pending); }
      return jsonResponse(value);
    }, { setTimeout: (f, ms) => (timers.push({ f, ms }), timers.length), clearTimeout() {} });
    const c = JSON.parse(h.elements["iscsi-document"].value), text = h.elements["iscsi-document"].value, previous = timers.length;
    const work = scopedISCSIEdit(h, c, "target-state", { state: "disabled" }); await settleUI();
    assert.equal(calls, 2); assert.equal(h.elements["iscsi-edit-submit"].disabled, true); assert.equal(h.elements["iscsi-edit-fields"].disabled, true);
    assert.equal(h.elements["iscsi-load"].disabled, true); await iscsiClick(h, "iscsi-edit-submit"); assert.equal(calls, 2);
    assert.equal(timers.length, previous + 1); assert.equal(timers.at(-1).ms, 10000);
    if (boundary === "field") h.elements["iscsi-edit-state"].listeners.get("input")();
    if (["input", "programmatic"].includes(boundary)) h.elements["iscsi-document"].value = "new manual text";
    if (boundary === "input") h.elements["iscsi-document"].listeners.get("input")();
    if (boundary === "clear") await iscsiClick(h, "iscsi-clear");
    if (boundary === "session") h.context.showAuthUnavailable();
    if (boundary === "deadline") timers.at(-1).f();
    const late = phase === "fetch" ? jsonResponse(candidate) : candidate;
    if (boundary === "programmatic") release(late);
    await work; if (boundary !== "programmatic") release(late); await settleUI();
    const expected = ["clear", "session"].includes(boundary) ? "" : ["input", "programmatic"].includes(boundary) ? "new manual text" : text;
    assert.equal(h.elements["iscsi-document"].value, expected, `${phase}/${boundary}`);
    assert.equal(h.elements["iscsi-result"].hidden, true); assert.equal(h.elements["iscsi-review-save"].disabled, true);
    assert.equal(h.elements["iscsi-edit-submit"].disabled, false); assert.equal(h.requests.some(r => r.options?.method === "PUT"), false);
    if (["clear", "session"].includes(boundary)) for (const key of ["mode", "target-id", "name", "state", "lun-id", "initiator", "access"]) assert.equal(h.elements[`iscsi-edit-${key}`].value, "");
  }
}
await testISCSIScopedLateRepliesAndRetirement();

process.stdout.write("Dashboard UI interaction smoke tests passed (DOM fixture; no visual browser coverage).\n");
