// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

const byId = (id) => document.getElementById(id);
const mib = (bytes) => `${(bytes / (1024 * 1024)).toFixed(0)} MiB`;
const gib = (bytes) => `${(bytes / (1024 ** 3)).toFixed(bytes >= 1024 ** 4 ? 1 : 0)} ${bytes >= 1024 ** 4 ? "TiB" : "GiB"}`;

function setText(id, value) {
  byId(id).textContent = String(value);
}

function formatUptime(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "Uptime unavailable";
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m uptime`;
}

function formatObservedTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return null;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function setConnectionState(label, state = "ready") {
  setText("build-label", label);
  const indicator = byId("service-status-dot");
  indicator.classList.toggle("is-loading", state === "loading");
  indicator.classList.toggle("is-degraded", state === "degraded");
  indicator.classList.toggle("is-unavailable", state === "unavailable");
}

function renderSystem(system) {
  const buildLabel = system.target === "qemu-armv5" ? "QEMU · EMULATED" :
    system.target === "ui-preview-fixture" ? "LOCAL FIXTURES" : "DEVELOPMENT PROFILE";
  setConnectionState(buildLabel);
  const profileNotice = system.target === "qemu-armv5" ? {
    title: "Emulator only.",
    copy: "This image is not flashable or validated on EX4 hardware. No production disks or NAND are accessed.",
    mark: "HARDWARE NOT VALIDATED",
  } : system.target === "ui-preview-fixture" ? {
    title: "Synthetic preview.",
    copy: "Every value in this view is generated fixture data. No device, disk, or emulator was examined.",
    mark: "FIXTURE DATA",
  } : {
    title: "Development image.",
    copy: "This target is not release-qualified. Values are observations only and do not authorize storage or firmware actions.",
    mark: "NOT RELEASE QUALIFIED",
  };
  setText("profile-notice-title", profileNotice.title);
  setText("profile-notice-copy", profileNotice.copy);
  setText("profile-notice-mark", profileNotice.mark);
  if (system.target === "ui-preview-fixture") byId("logout").hidden = true;
  setText("kernel-value", `Linux ${system.kernel}`);
  setText("runtime-value", `${system.architecture}${system.goarm ? ` · GOARM ${system.goarm}` : ""} · ${formatUptime(system.uptime_seconds)}`);
  setText("target-value", system.target || "Target unspecified");
  const total = Number(system.memory?.total_bytes) || 0;
  const available = Number(system.memory?.available_bytes) || 0;
  if (total > 0 && available <= total) {
    const used = total - available;
    const availablePercent = Math.max(0, Math.min(100, (available / total) * 100));
    setText("memory-value", `${mib(available)} available`);
    setText("memory-detail", `${mib(used)} in use of ${mib(total)}`);
    byId("memory-meter").style.width = `${availablePercent}%`;
    const meter = byId("memory-meter").parentElement;
    meter.setAttribute("aria-valuenow", String(Math.round(availablePercent)));
    meter.setAttribute("aria-label", `${Math.round(availablePercent)} percent memory available`);
  } else {
    setText("memory-value", "Unavailable");
    setText("memory-detail", "Memory values were missing or inconsistent");
    byId("memory-meter").style.width = "0";
    byId("memory-meter").parentElement.setAttribute("aria-valuenow", "0");
    byId("memory-meter").parentElement.setAttribute("aria-label", "Memory availability unavailable");
  }
  setText("firmware-value", system.mode || "Mode unspecified");
  const yesNoUnknown = (value) => value === true ? "yes" : value === false ? "no" : "unknown";
  setText("firmware-detail", `Flashable: ${yesNoUnknown(system.flashable)} · Hardware validated: ${yesNoUnknown(system.hardware_validated)}`);
  const observedAt = byId("observed-at");
  const formattedTime = formatObservedTime(system.observed_at);
  observedAt.textContent = formattedTime ? `Last observed ${formattedTime}` : "Observation time unavailable";
  if (formattedTime) observedAt.dateTime = new Date(system.observed_at).toISOString();
  else observedAt.removeAttribute("datetime");
}

function makeIdentityChip(label, status) {
  const chip = document.createElement("span");
  chip.className = `identity-chip ${["present", "invalid", "ambiguous", "unreadable"].includes(status) ? status : ""}`;
  chip.textContent = `${label} ${status || "unknown"}`;
  return chip;
}

function renderStorage(storage) {
  const list = byId("device-list");
  list.replaceChildren();
  const observations = Array.isArray(storage.observations) ? storage.observations : [];
  setText("device-count", `${observations.length} ${observations.length === 1 ? "device" : "devices"}`);
  if (observations.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No block devices are currently visible to this kernel.";
    list.append(empty);
    return;
  }
  for (const item of observations) {
    const row = document.createElement("article");
    row.className = "device-row";
    const name = document.createElement("div");
    name.className = "device-name";
    const glyph = document.createElement("span");
    glyph.className = "drive-glyph";
    glyph.setAttribute("aria-hidden", "true");
    glyph.textContent = "▤";
    const label = document.createElement("span");
    label.append(document.createTextNode(item.name || "unnamed"));
    const kind = document.createElement("small");
    kind.className = "device-kind";
    kind.textContent = `${item.kind || "block"} · ${item.major ?? "?"}:${item.minor ?? "?"}`;
    label.append(kind);
    name.append(glyph, label);

    const capacity = document.createElement("span");
    capacity.className = "device-capacity";
    capacity.textContent = Number.isFinite(Number(item.size_bytes)) ? gib(Number(item.size_bytes)) : "Unknown";

    const identities = document.createElement("div");
    identities.className = "identity-list";
    if (item.kind === "partition") {
      identities.append(makeIdentityChip("partition", `#${item.partition_number ?? "?"}`));
    } else {
      identities.append(makeIdentityChip("serial", item.serial_status), makeIdentityChip("WWN", item.wwn_status));
    }

    const access = document.createElement("span");
    access.className = `access-label${item.read_only ? " read-only" : ""}`;
    access.textContent = item.read_only ? "Kernel read-only" : "Observed only";
    row.append(name, capacity, identities, access);
    list.append(row);
  }
}

function renderArrays(inventory) {
  const list = byId("array-list");
  list.replaceChildren();
  const arrays = Array.isArray(inventory.arrays) ? inventory.arrays : [];
  const status = inventory.status || "unavailable";
  const count = Number(inventory.array_count);
  const visibleCount = Number.isInteger(count) ? count : arrays.length;
  setText("array-count", status === "available" ?
    `${visibleCount} ${visibleCount === 1 ? "array" : "arrays"}` :
    `RAID ${status}`);

  if (arrays.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = status === "available" ? "No software RAID arrays are currently visible to this kernel." :
      status === "unsupported" ? "This kernel does not expose RAID status; health is unknown." :
        "RAID inventory is incomplete or unavailable. No health conclusion is shown.";
    list.append(empty);
    return;
  }

  for (const array of arrays) {
    const row = document.createElement("article");
    row.className = "array-row";
    const title = document.createElement("div");
    title.className = "array-title";
    const name = document.createElement("strong");
    name.textContent = array.name || "unnamed array";
    const level = document.createElement("small");
    level.textContent = array.level || "level unknown";
    title.append(name, level);

    const health = document.createElement("span");
    health.className = `array-health array-health-${["healthy", "degraded", "syncing", "paused", "inactive"].includes(array.health) ? array.health : "unknown"}`;
    health.textContent = array.health || "unknown";

    const deviceState = document.createElement("span");
    const expected = Number(array.expected_devices);
    const active = Number(array.active_devices);
    const degraded = Number(array.degraded_devices);
    deviceState.textContent = Number.isInteger(expected) && Number.isInteger(active) ?
      `${active}/${expected} active${degraded > 0 ? ` · ${degraded} degraded` : ""}` : "device counts unavailable";

    const members = document.createElement("span");
    const names = Array.isArray(array.members) ? array.members.map((member) => member.name).filter(Boolean) : [];
    members.textContent = names.length > 0 ? `Members: ${names.join(", ")}` : "Member list unavailable";

    const sync = document.createElement("span");
    const progress = Number(array.sync_progress_percent);
    sync.textContent = array.sync_action && array.sync_action !== "idle" ?
      `${array.sync_action}${Number.isFinite(progress) ? ` · ${progress.toFixed(1)}%` : " · progress unavailable"}` :
      "No sync action reported";
    row.append(title, health, deviceState, members, sync);
    list.append(row);
  }
}

function renderMounts(inventory) {
  const list = byId("mount-list");
  list.replaceChildren();
  const mounts = Array.isArray(inventory.mounts) ? inventory.mounts : [];
  const count = Number(inventory.mount_count);
  const visibleCount = Number.isInteger(count) ? count : mounts.length;
  setText("mount-count", `${visibleCount} ${visibleCount === 1 ? "mount" : "mounts"}`);

  if (mounts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No mount entries are currently visible in this process namespace.";
    list.append(empty);
    return;
  }

  for (const mount of mounts) {
    const row = document.createElement("article");
    row.className = "mount-row";
    const point = document.createElement("strong");
    point.className = "mount-point";
    point.textContent = mount.mount_point || "Mount point unavailable";
    const filesystem = document.createElement("span");
    filesystem.textContent = mount.filesystem || "Filesystem unknown";
    const device = document.createElement("span");
    const major = Number(mount.device_major);
    const minor = Number(mount.device_minor);
    device.textContent = Number.isInteger(major) && Number.isInteger(minor) ? `${major}:${minor}` : "Device ID unavailable";
    const access = document.createElement("span");
    access.className = `mount-access${mount.read_only ? " read-only" : ""}`;
    access.textContent = mount.read_only ? "Read-only mount flag" : "Read-write mount flag";
    row.append(point, filesystem, device, access);
    list.append(row);
  }
}

function clearSystemObservation() {
  setText("kernel-value", "Unavailable");
  setText("runtime-value", "No current system observation");
  setText("target-value", "Target unavailable");
  setText("memory-value", "Unavailable");
  setText("memory-detail", "No current memory sample");
  byId("memory-meter").style.width = "0";
  byId("memory-meter").parentElement.setAttribute("aria-valuenow", "0");
  byId("memory-meter").parentElement.setAttribute("aria-label", "Memory availability unavailable");
  setText("firmware-value", "Unavailable");
  setText("firmware-detail", "Current hardware and flashability state unavailable");
  setText("observed-at", "No current system observation");
  byId("observed-at").removeAttribute("datetime");
  setText("profile-notice-title", "System profile unavailable.");
  setText("profile-notice-copy", "System metadata could not be refreshed. No previous system values are shown.");
  setText("profile-notice-mark", "NO CURRENT SYSTEM DATA");
}

function clearStorageObservation() {
  setText("device-count", "Storage unavailable");
  const empty = document.createElement("p");
  empty.className = "empty-state";
  empty.textContent = "Storage observation unavailable. No current device values are shown.";
  byId("device-list").replaceChildren(empty);
}

function clearArrayObservation() {
  setText("array-count", "RAID unavailable");
  const empty = document.createElement("p");
  empty.className = "empty-state";
  empty.textContent = "RAID observation unavailable. No current array health is shown.";
  byId("array-list").replaceChildren(empty);
}

function clearMountObservation() {
  setText("mount-count", "Mounts unavailable");
  const empty = document.createElement("p");
  empty.className = "empty-state";
  empty.textContent = "Mount observation unavailable. No current mount values are shown.";
  byId("mount-list").replaceChildren(empty);
}

async function fetchJSON(path) {
  const response = await fetch(path, { method: "GET", headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" });
  if (!response.ok) {
    const failure = new Error("diagnostics unavailable");
    failure.status = response.status;
    throw failure;
  }
  return response.json();
}

async function refreshSnapshot() {
  const button = byId("refresh");
  const error = byId("error-banner");
  const status = byId("snapshot-status");
  const label = byId("refresh-label");
  const originalLabel = label.textContent;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  label.textContent = "Refreshing…";
  status.textContent = "Refreshing the read-only snapshot…";
  error.hidden = true;
  setConnectionState("Refreshing snapshot…", "loading");
  try {
    const [systemResult, storageResult, arraysResult, mountsResult] = await Promise.allSettled([
      fetchJSON("/api/v1/system"),
      fetchJSON("/api/v1/storage"),
      fetchJSON("/api/v1/arrays"),
      fetchJSON("/api/v1/mounts"),
    ]);
    const results = [systemResult, storageResult, arraysResult, mountsResult];
    if (results.some((result) => result.status === "rejected" && result.reason?.status === 401)) {
      status.textContent = "Session expired. Sign in again to view a current snapshot.";
      try {
        await updateAuthView({ refresh: false, notice: "Your session expired. Sign in again to continue." });
      } catch {
        showAuthUnavailable();
      }
      return;
    }

    const systemCurrent = systemResult.status === "fulfilled";
    const storageCurrent = storageResult.status === "fulfilled";
    const arraysCurrent = arraysResult.status === "fulfilled";
    const mountsCurrent = mountsResult.status === "fulfilled";
    if (systemCurrent) renderSystem(systemResult.value);
    else clearSystemObservation();
    if (storageCurrent) renderStorage(storageResult.value);
    else clearStorageObservation();
    if (arraysCurrent) renderArrays(arraysResult.value);
    else clearArrayObservation();
    if (mountsCurrent) renderMounts(mountsResult.value);
    else clearMountObservation();

    if (systemCurrent && storageCurrent && arraysCurrent && mountsCurrent) {
      status.textContent = "Read-only system, storage, RAID, and mount observations updated.";
      return;
    }

    const failedDomains = [
      !systemCurrent && "system",
      !storageCurrent && "storage",
      !arraysCurrent && "RAID",
      !mountsCurrent && "mount",
    ].filter(Boolean);
    const currentDomains = [
      systemCurrent && "system",
      storageCurrent && "storage",
      arraysCurrent && "RAID",
      mountsCurrent && "mount",
    ].filter(Boolean);
    const failureSummary = `${failedDomains.join(", ")} observation${failedDomains.length === 1 ? "" : "s"} unavailable.`;
    const currentSummary = currentDomains.length > 0 ?
      `${currentDomains.join(", ")} observation${currentDomains.length === 1 ? " is" : "s are"} current.` :
      "No observations are current.";
    setConnectionState(failedDomains.length === 4 ? "API unavailable" : "Partial snapshot", failedDomains.length === 4 ? "unavailable" : "degraded");
    status.textContent = failedDomains.length === 4 ?
      "System, storage, RAID, and mount observations unavailable. Current values were cleared." :
      `${currentSummary} ${failureSummary} Failed values were cleared.`;
    error.textContent = failedDomains.length === 4 ?
      "System, storage, RAID, and mount observations are unavailable. No current values are shown." :
      `${currentSummary} ${failureSummary} No previous values are shown for the unavailable section.`;
    error.hidden = false;
  } catch (failure) {
    if (failure?.status === 401) {
      status.textContent = "Session expired. Sign in again to view a current snapshot.";
      try {
        await updateAuthView({ refresh: false, notice: "Your session expired. Sign in again to continue." });
      } catch {
        showAuthUnavailable();
      }
      return;
    }
    clearSystemObservation();
    clearStorageObservation();
    clearArrayObservation();
    clearMountObservation();
    setConnectionState("API unavailable", "unavailable");
    status.textContent = "System, storage, RAID, and mount observations unavailable. Current values were cleared.";
    error.textContent = "System, storage, RAID, and mount observations are unavailable. No current values are shown.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    label.textContent = originalLabel;
  }
}

function setAuthError(message) {
  const error = byId("auth-error");
  error.textContent = message;
  error.hidden = false;
}

function showAuthUnavailable() {
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  byId("auth-panel").hidden = false;
  byId("dashboard-content").hidden = true;
  byId("logout").hidden = true;
  byId("auth-form").hidden = true;
  byId("auth-retry").hidden = false;
  byId("auth-password").value = "";
  setText("auth-title", "Local API unavailable.");
  setText("auth-description", "Sign-in status cannot be checked right now, so diagnostic data is hidden. Retry after the local service is available.");
  setAuthError("The local API could not be reached. No current system or storage data is shown.");
  setConnectionState("API unavailable", "unavailable");
}

async function updateAuthView({ refresh = true, notice = "" } = {}) {
  const status = await fetchJSON("/api/v1/auth/status");
  const authPanel = byId("auth-panel");
  const dashboard = byId("dashboard-content");
  const logout = byId("logout");
  const form = byId("auth-form");
  const password = byId("auth-password");
  const submit = byId("auth-submit");
  const authError = byId("auth-error");
  authError.hidden = true;
  form.hidden = false;
  byId("auth-retry").hidden = true;

  if (status.authenticated) {
    authPanel.hidden = true;
    dashboard.hidden = false;
    logout.hidden = false;
    setConnectionState("Authenticated", "loading");
    if (refresh) await refreshSnapshot();
    return;
  }

  dashboard.hidden = true;
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  logout.hidden = true;
  authPanel.hidden = false;
  form.dataset.mode = status.setup_required ? "setup" : "login";
  setText("auth-title", status.setup_required ? "Set up your administrator account." : "Sign in to PhantoWD.");
  setText("auth-description", status.setup_required ?
    "This initial account is stored in the configured system-state directory. Use at least 15 characters; a longer passphrase is better." :
    "Enter your local administrator credentials to view the system snapshot.");
  submit.textContent = status.setup_required ? "Create account" : "Sign in";
  password.autocomplete = status.setup_required ? "new-password" : "current-password";
  password.value = "";
  setConnectionState("Sign-in required");
  if (notice) setAuthError(notice);
}

byId("auth-retry").addEventListener("click", async () => {
  const retry = byId("auth-retry");
  retry.disabled = true;
  setConnectionState("Checking local API…", "loading");
  try {
    await updateAuthView();
  } catch {
    showAuthUnavailable();
  } finally {
    retry.disabled = false;
  }
});

byId("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = byId("auth-form");
  const submit = byId("auth-submit");
  const error = byId("auth-error");
  const username = byId("auth-username").value;
  const password = byId("auth-password").value;
  const route = form.dataset.mode === "setup" ? "/api/v1/auth/setup" : "/api/v1/auth/login";
  if (route === "/api/v1/auth/setup" && [...password].length < 15) {
    setAuthError("Use a passphrase with at least 15 characters.");
    return;
  }
  if (new TextEncoder().encode(password).length > 1024) {
    setAuthError("The password is longer than the 1024-byte limit.");
    return;
  }
  submit.disabled = true;
  error.hidden = true;
  try {
    const response = await fetch(route, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      credentials: "same-origin",
      cache: "no-store",
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const message = response.status === 400 ? "Check the username and password requirements." :
        response.status === 401 ? "The username or password is not correct." :
          response.status === 409 ? "Account setup is no longer available. Reload and sign in." :
            response.status === 429 ? "Too many attempts. Wait one minute before trying again." :
              "The authentication service is temporarily unavailable.";
      throw new Error(message);
    }
    byId("auth-password").value = "";
    await updateAuthView();
  } catch (failure) {
    setAuthError(failure instanceof Error ? failure.message : "Authentication request failed.");
  } finally {
    submit.disabled = false;
  }
});

byId("logout").addEventListener("click", async () => {
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  const logout = byId("logout");
  logout.disabled = true;
  try {
    const session = await fetchJSON("/api/v1/auth/session");
    const response = await fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: { Accept: "application/json", "X-PhantoWD-CSRF": session.csrf_token },
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("Could not safely end the session.");
    await updateAuthView();
  } catch {
    const error = byId("error-banner");
    error.textContent = "Sign out failed. Reload this page and try again.";
    error.hidden = false;
  } finally {
    logout.disabled = false;
  }
});

// Standalone desired-policy builder: no current configuration is loaded,
// no draft is persisted, and no activation route exists here.
const policyFields = ["uuid", "name", "path", "user", "smb-access", "nfs-enabled", "export-id", "network", "nfs-access", "squash", "uid", "gid", "security"];
let policyGeneration = 0;
let policyBusy = false;
const requirementLabels = {
  runtime_volume_identity: "Prove the expected volume is present, unique and compatible.",
  path_and_mount_containment: "Verify paths stay within the qualified mounted filesystem.",
  unix_accounts_and_effective_access: "Provision file-service accounts and verify effective filesystem permissions.",
  durable_configuration: "Provision durable configuration and recovery.",
  service_activation_lifecycle: "Qualify service activation, failure handling and rollback.",
  cross_protocol_access_review: "Review SMB and NFS access independently; SMB grants do not restrict NFS.",
  auth_sys_network_trust: "AUTH_SYS requires trusted clients and network; it does not cryptographically verify client IDs.",
  kerberos_provisioning: "Provision Kerberos before using this security flavor.",
};

function invalidatePolicyPreview(message = "Draft changed. Validate again to see a current preview.") {
  invalidateServiceDraft();
  policyGeneration++;
  byId("policy-result").hidden = true;
  byId("policy-error").hidden = true;
  setText("policy-samba", "");
  setText("policy-nfs", "");
  byId("policy-requirements").replaceChildren();
  setText("policy-status", message);
}

function syncPolicyNFS() {
  const enabled = byId("policy-nfs-enabled").value === "on";
  byId("policy-nfs-fields").hidden = !enabled;
  byId("policy-nfs-fields").disabled = !enabled;
}

function clearPolicyDraft() {
  invalidatePolicyPreview("No proposal validated.");
  const defaults = { "smb-access": "ro", "nfs-enabled": "off", "nfs-access": "ro", squash: "all", uid: "65534", gid: "65534", security: "sys" };
  for (const field of policyFields) byId(`policy-${field}`).value = defaults[field] ?? "";
  syncPolicyNFS();
}

function buildPolicyProposal() {
  const value = (field) => byId(`policy-${field}`).value;
  const shares = {
    format: "phantowd-share-config", schema_version: 1, revision: 1,
    volumes: [{ id: "draft-volume", filesystem_uuid: value("uuid") }],
    users: [{ id: "draft-user", name: value("user") }],
    shares: [{ id: "draft-share", name: value("name"), volume_id: "draft-volume", relative_path: value("path"), grants: [{ user_id: "draft-user", access: value("smb-access") }] }],
  };
  const nfs = { format: "phantowd-nfs-policy", schema_version: 1, revision: 1, volume_revision: 1, exports: [] };
  if (value("nfs-enabled") === "on") {
    const numericID = (field) => {
      const raw = value(field);
      if (!/^[1-9][0-9]*$/.test(raw) || Number(raw) > 4294967294) throw new Error("Anonymous UID and GID must be whole numbers from 1 to 4294967294.");
      return Number(raw);
    };
    nfs.exports.push({ id: value("export-id"), volume_id: "draft-volume", relative_path: value("path"), clients: [{ network: value("network"), access: value("nfs-access"), squash: value("squash"), anonymous_uid: numericID("uid"), anonymous_gid: numericID("gid"), security: value("security") }] });
  }
  return { shares, nfs };
}

function validatePolicyPreview(preview) {
  if (preview?.schema_version !== 1 || preview.scope !== "desired-policy-only" ||
      ["persisted", "applied", "runtime_validated", "activation_available"].some((key) => preview[key] !== false) ||
      !Array.isArray(preview.requirements) || preview.requirements.length > 16 ||
      !preview.requirements.every((key) => Object.hasOwn(requirementLabels, key)) ||
      !["runtime_volume_identity", "path_and_mount_containment", "unix_accounts_and_effective_access", "durable_configuration", "service_activation_lifecycle"].every((key) => preview.requirements.includes(key)) ||
      typeof preview.samba?.samba_share_sections !== "string" || typeof preview.nfs?.exports_table !== "string" ||
      preview.samba.samba_share_sections.length > 65536 || preview.nfs.exports_table.length > 65536) {
    throw new Error("The API returned an unsupported preview. Nothing was applied.");
  }
}

function renderPolicyPreview(preview) {
  validatePolicyPreview(preview);
  for (const requirement of preview.requirements) {
    const item = document.createElement("li");
    item.textContent = requirementLabels[requirement];
    byId("policy-requirements").append(item);
  }
  setText("policy-samba", preview.samba.samba_share_sections || "No SMB sections.");
  setText("policy-nfs", preview.nfs.exports_table || "No NFS exports.");
  byId("policy-result").hidden = false;
  setText("policy-status", "Desired-policy validation passed. Not saved or applied; runtime access remains unverified.");
}

async function submitPolicyProposal(event) {
  event.preventDefault();
  if (policyBusy) return;
  invalidatePolicyPreview("Validating the proposal...");
  const generation = policyGeneration;
  const button = byId("policy-submit");
  policyBusy = true;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const body = JSON.stringify(buildPolicyProposal());
    if (new TextEncoder().encode(body).length > 524544) throw new Error("The proposal exceeds the request size limit.");
    const sessionResponse = await fetch("/api/v1/auth/session", { method: "GET", credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" }, signal: controller.signal });
    if (sessionResponse.status === 401) {
      const failure = new Error("Session expired. Sign in again."); failure.status = 401; throw failure;
    }
    if (!sessionResponse.ok) throw new Error("Cannot verify the session. Retry after signing in.");
    const session = await sessionResponse.json();
    if (typeof session.csrf_token !== "string" || !session.csrf_token) throw new Error("The session token is unavailable.");
    if (generation !== policyGeneration) return;
    const response = await fetch("/api/v1/file-services/preview", {
      method: "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": session.csrf_token }, body,
    });
    if (generation !== policyGeneration) return;
    if (!response.ok) {
      const message = response.status === 422 ? "Policy rejected. Check UUIDs, relative path, username, access and canonical client CIDR. No service was changed." :
        response.status === 401 ? "Session expired. Sign in again." :
          response.status === 403 ? "Session security check failed. Reload and sign in again." :
            response.status === 503 ? "Preview service busy. Retry shortly." : "The proposal could not be validated. Nothing was applied.";
      const failure = new Error(message); failure.status = response.status; throw failure;
    }
    const preview = await response.json();
    if (generation !== policyGeneration) return;
    renderPolicyPreview(preview);
  } catch (failure) {
    if (generation !== policyGeneration) return;
    if (failure?.status === 401) {
      try { await updateAuthView({ refresh: false, notice: "Session expired. Sign in again." }); }
      catch { showAuthUnavailable(); }
    } else {
      setText("policy-error", failure?.name === "AbortError" ? "Preview timed out. Retry; nothing was applied." : failure instanceof Error ? failure.message : "Preview unavailable. Nothing was applied.");
      byId("policy-error").hidden = false;
      setText("policy-status", "No current validated preview.");
    }
  } finally {
    clearTimeout(timeout);
    policyBusy = false;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

let savedGeneration = 0;
let savedController = null;

function clearSavedPolicy(message = "Not loaded. No stored configuration is shown.") {
  savedGeneration += 1;
  savedController?.abort();
  savedController = null;
  byId("saved-result").hidden = true;
  byId("saved-shares").replaceChildren();
  setText("saved-summary", "");
  setText("saved-status", message);
  byId("saved-load").disabled = false;
  byId("saved-load").removeAttribute("aria-busy");
}

function validateSavedPolicy(response) {
  const invalid = () => { throw new Error("unsupported saved policy"); };
  if (response?.schema_version !== 1 || response.scope !== "stored-desired-share-policy-only" ||
      typeof response.initialized !== "boolean" || response.runtime_validated !== false || response.activation_available !== false) invalid();
  if (!response.initialized) {
    if (response.configuration !== null) invalid();
    return null;
  }
  const c = response.configuration;
  if (!c || c.format !== "phantowd-share-config" || c.schema_version !== 1 || !Number.isSafeInteger(c.revision) || c.revision < 1 ||
      !Array.isArray(c.volumes) || c.volumes.length > 16 || !Array.isArray(c.users) || c.users.length > 128 || !Array.isArray(c.shares) || c.shares.length > 128) invalid();
  const text = (value, max) => typeof value === "string" && value.length > 0 && value.length <= max;
  const id = (value) => text(value, 64) && /^[a-z][a-z0-9-]*$/.test(value);
  const volumes = new Map();
  const uuids = new Set();
  const users = new Map();
  const names = new Set();
  for (const v of c.volumes) {
    if (!v || !id(v.id) || volumes.has(v.id) || typeof v.filesystem_uuid !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.filesystem_uuid) ||
        v.filesystem_uuid === "00000000-0000-0000-0000-000000000000" || uuids.has(v.filesystem_uuid)) invalid();
    volumes.set(v.id, v); uuids.add(v.filesystem_uuid);
  }
  for (const u of c.users) {
    if (!u || !id(u.id) || users.has(u.id) || !text(u.name, 32) || !/^[a-z][a-z0-9_-]*$/.test(u.name) || names.has(u.name)) invalid();
    users.set(u.id, u.name); names.add(u.name);
  }
  const shareIDs = new Set();
  const shareNames = new Set();
  for (const s of c.shares) {
    if (!s || !id(s.id) || shareIDs.has(s.id) || !text(s.name, 80) || shareNames.has(s.name.toLowerCase()) || !volumes.has(s.volume_id) ||
        !text(s.relative_path, 1024) || !Array.isArray(s.grants) || s.grants.length === 0 || s.grants.length > 128) invalid();
    shareIDs.add(s.id); shareNames.add(s.name.toLowerCase());
    const granted = new Set();
    for (const g of s.grants) {
      if (!g || !users.has(g.user_id) || granted.has(g.user_id) || !["ro", "rw"].includes(g.access)) invalid();
      granted.add(g.user_id);
    }
  }
  return { config: c, volumes, users };
}

function renderSavedPolicy(response) {
  const parsed = validateSavedPolicy(response);
  if (parsed === null) {
    setText("saved-status", "Storage is configured, but no share policy has been initialized. This is not an empty saved configuration.");
    return;
  }
  const { config, volumes, users } = parsed;
  const rows = config.shares.map((share) => {
    const row = document.createElement("li");
    const title = document.createElement("strong"); title.textContent = share.name;
    const path = document.createElement("span"); path.textContent = `${share.volume_id} / ${share.relative_path}`;
    const identity = document.createElement("span"); identity.textContent = `Expected filesystem UUID: ${volumes.get(share.volume_id).filesystem_uuid}`;
    const grants = document.createElement("details");
    const summary = document.createElement("summary"); summary.textContent = `${share.grants.length} desired access grant(s)`;
    const access = document.createElement("p");
    access.textContent = share.grants.map((grant) => `${users.get(grant.user_id)}: ${grant.access === "ro" ? "read only" : "read and write"}`).join("; ");
    grants.append(summary, access); row.append(title, path, identity, grants);
    return row;
  });
  byId("saved-shares").replaceChildren(...rows);
  setText("saved-summary", `Revision ${config.revision} · ${config.volumes.length} volume(s) · ${config.users.length} user(s) · ${config.shares.length} share(s)`);
  setText("saved-status", config.shares.length === 0 ? "Saved configuration loaded: no shares are defined. No service was changed." : "Saved configuration loaded. Runtime access has not been verified; no service was changed.");
  byId("saved-result").hidden = false;
}

async function loadSavedPolicy() {
  if (savedController) return;
  clearSavedPolicy("Loading saved configuration… Previous values were cleared.");
  const generation = savedGeneration;
  const controller = new AbortController();
  savedController = controller;
  const button = byId("saved-load");
  button.disabled = true; button.setAttribute("aria-busy", "true");
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("/api/v1/shares/configuration", { method: "GET", credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" }, signal: controller.signal });
    if (generation !== savedGeneration) return;
    if (response.status === 401) {
      clearSavedPolicy();
      byId("dashboard-content").hidden = true;
      try {
        await updateAuthView({ refresh: false, notice: "Session expired. Sign in again." });
      } catch {
        showAuthUnavailable();
      }
      return;
    }
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      if (generation !== savedGeneration) return;
      setText("saved-status", response.status === 503 && body.error === "share_configuration_not_configured" ?
        "Configuration storage is not connected in this build. No saved policy is available through the API." :
        "Saved configuration is unavailable or busy. No previous values are shown; retry later. No service was changed.");
      return;
    }
    const body = await response.json();
    if (generation !== savedGeneration) return;
    renderSavedPolicy(body);
  } catch (failure) {
    if (generation !== savedGeneration) return;
    setText("saved-status", failure?.name === "AbortError" ? "Configuration read timed out. No saved values are shown." : "Saved configuration could not be verified. No saved values are shown.");
  } finally {
    clearTimeout(timeout);
    if (generation === savedGeneration) {
      savedController = null;
      button.disabled = false; button.removeAttribute("aria-busy");
    }
  }
}

byId("saved-load").addEventListener("click", loadSavedPolicy);
byId("service-load").addEventListener("click", loadServicePolicy);
byId("service-prepare").addEventListener("click", prepareServiceAddition);
byId("service-save").addEventListener("click", saveServiceAddition);
byId("policy-form").addEventListener("submit", submitPolicyProposal);
byId("policy-form").addEventListener("input", () => { invalidatePolicyPreview(); syncPolicyNFS(); });
byId("policy-form").addEventListener("change", () => { invalidatePolicyPreview(); syncPolicyNFS(); });
byId("policy-clear").addEventListener("click", clearPolicyDraft);
byId("refresh").addEventListener("click", refreshSnapshot);
updateAuthView().catch(showAuthUnavailable);
