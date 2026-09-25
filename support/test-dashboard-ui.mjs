// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Dependency-free browser-DOM smoke tests for the embedded dashboard logic.
// This does not claim visual browser or assistive-technology coverage.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, Script } from "node:vm";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = await readFile(join(repoRoot, "src/phantowd-api/ui/app.js"), "utf8");

class FixtureElement {
  constructor() {
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
}

function jsonResponse(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function systemFixture() {
  return {
    target: "qemu-armv5",
    mode: "development",
    flashable: false,
    hardware_validated: false,
    observed_at: "2026-09-25T12:30:00Z",
    architecture: "arm",
    goarm: "5",
    kernel: "6.18.53",
    uptime_seconds: 123456,
    memory: { total_bytes: 256 * 1024 * 1024, available_bytes: 96 * 1024 * 1024 },
  };
}

function arraysFixture() {
  return {
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

async function createHarness(respond) {
  const ids = [
    "auth-panel", "auth-title", "auth-description", "auth-form", "auth-username",
    "auth-password", "auth-submit", "auth-retry", "auth-error", "dashboard-content",
    "logout", "refresh", "refresh-label", "snapshot-status", "error-banner",
    "service-status-dot", "build-label", "kernel-value", "runtime-value", "target-value",
    "memory-value", "memory-detail", "memory-meter", "firmware-value", "firmware-detail",
    "profile-notice-title", "profile-notice-copy", "profile-notice-mark",
    "observed-at", "device-count", "device-list", "array-count", "array-list", "mount-count", "mount-list",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FixtureElement()]));
  elements["refresh-label"].textContent = "Refresh snapshot";
  elements["memory-meter"].parentElement = new FixtureElement();
  const document = {
    getElementById: (id) => elements[id] ?? null,
    createElement: () => new FixtureElement(),
    createTextNode: (text) => ({ textContent: String(text) }),
  };
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
    setTimeout,
  });
  new Script(source).runInContext(context);
  await new Promise((resolve) => setImmediate(resolve));
  return { context, elements, requests };
}

async function testReadOnlySnapshotAndSafeRendering() {
  const { context, elements, requests } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") {
      return jsonResponse({ observations: [{
        name: "disk<script>", kind: "disk", major: 8, minor: 0,
        size_bytes: 2 ** 40, serial_status: "present", wwn_status: "unavailable", read_only: true,
      }] });
    }
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  assert.equal(elements["auth-panel"].hidden, true);
  assert.equal(elements["dashboard-content"].hidden, false);
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.53");
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
    if (path === "/api/v1/storage") return jsonResponse({ observations: [] });
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

async function testStorageFailureKeepsOnlyCurrentSystemObservation() {
  let storageAvailable = true;
  const { context, elements } = await createHarness(async (path) => {
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") {
      return storageAvailable ? jsonResponse({ observations: [{ name: "sda", kind: "block", major: 8, minor: 0, size_bytes: 2 ** 40 }] }) : jsonResponse({ error: "unavailable" }, 503);
    }
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request: ${path}`);
  });

  storageAvailable = false;
  await context.refreshSnapshot();
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.53");
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
    if (path === "/api/v1/storage") return jsonResponse({ observations: [{ name: "sda", kind: "block", major: 8, minor: 0, size_bytes: 2 ** 40 }] });
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
    if (path === "/api/v1/storage") return jsonResponse({ observations: [{ name: "sda", kind: "block", major: 8, minor: 0, size_bytes: 2 ** 40 }] });
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return mountsAvailable ? jsonResponse(mountsFixture()) : jsonResponse({ error: "unavailable" }, 503);
    throw new Error(`Unexpected request: ${path}`);
  });

  mountsAvailable = false;
  await context.refreshSnapshot();
  assert.equal(elements["kernel-value"].textContent, "Linux 6.18.53");
  assert.equal(elements["device-count"].textContent, "1 device");
  assert.equal(elements["array-count"].textContent, "2 arrays");
  assert.equal(elements["mount-count"].textContent, "Mounts unavailable");
  assert.match(elements["mount-list"].children[0].textContent, /no current mount values/i);
  assert.equal(elements["service-status-dot"].className.includes("is-degraded"), true);
  assert.match(elements["snapshot-status"].textContent, /system, storage, RAID.*current.*mount.*unavailable/i);
}

await testReadOnlySnapshotAndSafeRendering();
await testUnavailableAuthIsVisibleAndRetryable();
await testExpiredSessionReturnsToLogin();
await testStorageFailureKeepsOnlyCurrentSystemObservation();
await testSystemFailureKeepsOnlyCurrentStorageObservation();
await testAllDiagnosticFailuresClearValues();
await testMountFailureClearsOnlyMountObservation();
process.stdout.write("Dashboard UI interaction smoke tests passed (DOM fixture; no visual browser coverage).\n");
