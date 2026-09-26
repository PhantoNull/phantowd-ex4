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
const serviceSource = await readFile(join(repoRoot, "src/phantowd-api/ui/service-policy.js"), "utf8");
const markup = await readFile(join(repoRoot, "src/phantowd-api/ui/index.html"), "utf8");
const markupIDs = [...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
assert.equal(new Set(markupIDs).size, markupIDs.length, "duplicate HTML IDs");
for (const match of (source + serviceSource).matchAll(/(?:byId|setText)\("([^"]+)"/g)) {
  assert.ok(markupIDs.includes(match[1]), `script references missing HTML ID ${match[1]}`);
}
assert.match(markup, /id="policy-nfs-fields"[^>]*hidden disabled/);
assert.match(markup, /id="policy-form"[^>]*autocomplete="off"/);

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
    ...["load", "status", "result", "summary", "shares"].map((id) => `saved-${id}`),
    ...["load", "prepare", "save", "status", "current", "summary", "document", "review", "change", "samba", "nfs"].map((id) => `service-${id}`),
    ...["form", "submit", "clear", "result", "error", "status", "requirements", "samba", "nfs", "nfs-fields", "uuid", "name", "path", "user", "smb-access", "nfs-enabled", "export-id", "network", "nfs-access", "squash", "uid", "gid", "security"].map((id) => `policy-${id}`),
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
    AbortController,
    setTimeout,
    clearTimeout,
  });
  new Script(serviceSource).runInContext(context);
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
    if (path === "/api/v1/storage") return jsonResponse({ observations: [] });
    if (path === "/api/v1/arrays") return jsonResponse(arraysFixture());
    if (path === "/api/v1/mounts") return jsonResponse(mountsFixture());
    throw new Error(`Unexpected request ${path}`);
  });
}

async function testPolicyBuilderAndSafePreview() {
  const { context, elements, requests } = await policyHarness();
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
      if (path === "/api/v1/storage") return jsonResponse({ observations: [] });
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

async function serviceHarness(stateResponse, previewResponse = () => jsonResponse(policyFixture()), sessionResponse = () => jsonResponse({ csrf_token: "fixture-only" })) {
  return createHarness(async (path, options) => {
    if (path === "/api/v1/file-services/configuration") return stateResponse(options);
    if (path === "/api/v1/auth/status") return jsonResponse({ authenticated: true });
    if (path === "/api/v1/auth/session") return sessionResponse();
    if (path === "/api/v1/file-services/preview") return previewResponse(options);
    if (path === "/api/v1/system") return jsonResponse(systemFixture());
    if (path === "/api/v1/storage") return jsonResponse({ observations: [] });
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
  await context.saveServiceAddition();
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
  await context.loadServicePolicy();
  assert.match(elements["service-summary"].textContent, /no configuration initialized/);
  fillPolicy(elements);
  await context.prepareServiceAddition();
  assert.equal(elements["service-save"].disabled, false);
  assert.equal(elements["service-review"].hidden, false);
  assert.equal(requests.some(({ options }) => options?.method === "PUT"), false, "preview must not save");
  assert.match(elements["service-samba"].textContent, /<script>/, "render as text only");
  await context.saveServiceAddition();
  assert.equal(saved.revision, 1);
  assert.equal(saved.nfs.volume_revision, 1);
  assert.equal(saved.shares.volumes.length, 1);
  const previous = structuredClone(saved);
  assert.match(elements["service-status"].textContent, /confirmed saved.*No services were activated/);
  elements["policy-name"].value = "Comics"; elements["policy-path"].value = "comics";
  elements["policy-export-id"].value = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
  context.invalidatePolicyPreview();
  await context.prepareServiceAddition(); await context.saveServiceAddition();
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
    fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceAddition();
    assert.match(elements["service-status"].textContent, result === "conflict" ? /Revision conflict.*refused/ : /not confirmed.*may have committed/);
    assert.equal(elements["service-save"].disabled, true);
    assert.equal(elements["service-prepare"].disabled, true);
    await context.saveServiceAddition(); await context.prepareServiceAddition();
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
    fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceAddition();
    assert.equal(elements["service-current"].hidden, true);
    assert.equal(elements["service-save"].disabled, true);
    assert.equal(requests.some(({ options }) => options?.method === "PUT"), false);
    assert.doesNotMatch(elements["service-status"].textContent, /private failure/);
  }
  const { context, elements, requests } = await serviceHarness(() => jsonResponse(serviceReply(null)), () => jsonResponse({}, 422));
  fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceAddition();
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
    const operation = boundary === "preview" ? h.context.prepareServiceAddition() : boundary === "load" ? h.context.loadServicePolicy() : h.context.saveServiceAddition();
    await new Promise((resolve) => setImmediate(resolve));
    // Auth loss must cancel and prevent a late response from restoring sensitive data.
    h.context.showAuthUnavailable();
    release(jsonResponse(boundary === "preview" ? policyFixture() : boundary === "save-session" ? { csrf_token: "fixture-only" } : boundary === "load" ? serviceReply(null) : serviceSaved(1)));
    await operation;
    assert.equal(h.elements["service-review"].hidden, true);
    assert.equal(h.elements["service-current"].hidden, true);
    assert.equal(h.elements["service-document"].textContent, "");
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
    const operation = phase === "preview" ? context.prepareServiceAddition() : context.saveServiceAddition();
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
  fillPolicy(elements); await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceAddition();
  await context.loadServicePolicy(); await context.prepareServiceAddition(); await context.saveServiceAddition();
  assert.equal(elements["service-save"].disabled, true);
  assert.equal(elements["service-prepare"].disabled, true);
  assert.equal(elements["service-current"].hidden, true);
  assert.equal(requests.filter(({ options }) => options?.method === "PUT").length, 1);
}

await testServiceAddAndPreserve();
await testServiceUncertainAndConflict();
await testServiceRefusalsAndInvalidation();
await testServiceFormEditsAndReconcileFailure();
await testSavedPolicyStatesAndSafeRendering();
await testSavedPolicyMalformedReplies();
await testSavedPolicyLateRepliesAndAuthLoss();
await testPolicyBuilderAndSafePreview();
await testPolicyFailuresAndStaleResponses();
await testReadOnlySnapshotAndSafeRendering();
await testUnavailableAuthIsVisibleAndRetryable();
await testExpiredSessionReturnsToLogin();
await testStorageFailureKeepsOnlyCurrentSystemObservation();
await testSystemFailureKeepsOnlyCurrentStorageObservation();
await testAllDiagnosticFailuresClearValues();
await testMountFailureClearsOnlyMountObservation();
process.stdout.write("Dashboard UI interaction smoke tests passed (DOM fixture; no visual browser coverage).\n");
