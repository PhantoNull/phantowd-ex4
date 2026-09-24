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
  return Number.isNaN(date.valueOf()) ? "Observation time unavailable" : `Sampled ${date.toLocaleTimeString()}`;
}

function renderSystem(system) {
  const buildLabel = system.target === "qemu-armv5" ? "QEMU · EMULATED" :
    system.target === "ui-preview-fixture" ? "LOCAL FIXTURES" : "DEVELOPMENT PROFILE";
  setText("build-label", buildLabel);
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
  }
  setText("firmware-value", system.mode || "Mode unspecified");
  const yesNoUnknown = (value) => value === true ? "yes" : value === false ? "no" : "unknown";
  setText("firmware-detail", `Flashable: ${yesNoUnknown(system.flashable)} · Hardware validated: ${yesNoUnknown(system.hardware_validated)}`);
  setText("observed-at", formatObservedTime(system.observed_at));
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

async function fetchJSON(path) {
  const response = await fetch(path, { method: "GET", headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" });
  if (!response.ok) throw new Error("diagnostics unavailable");
  return response.json();
}

async function refreshSnapshot() {
  const button = byId("refresh");
  const error = byId("error-banner");
  button.disabled = true;
  error.hidden = true;
  try {
    const [system, storage] = await Promise.all([fetchJSON("/api/v1/system"), fetchJSON("/api/v1/storage")]);
    renderSystem(system);
    renderStorage(storage);
  } catch {
    setText("kernel-value", "Unavailable");
    setText("runtime-value", "No current system snapshot");
    setText("target-value", "Target unavailable");
    setText("memory-value", "Unavailable");
    setText("memory-detail", "No current memory sample");
    byId("memory-meter").style.width = "0";
    byId("memory-meter").parentElement.setAttribute("aria-valuenow", "0");
    setText("firmware-value", "Unavailable");
    setText("firmware-detail", "Current hardware and flashability state unavailable");
    setText("observed-at", "No current snapshot");
    setText("device-count", "— devices");
    byId("device-list").replaceChildren();
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function setAuthError(message) {
  const error = byId("auth-error");
  error.textContent = message;
  error.hidden = false;
}

async function updateAuthView() {
  const status = await fetchJSON("/api/v1/auth/status");
  const authPanel = byId("auth-panel");
  const dashboard = byId("dashboard-content");
  const logout = byId("logout");
  const form = byId("auth-form");
  const password = byId("auth-password");
  const submit = byId("auth-submit");
  const authError = byId("auth-error");
  authError.hidden = true;

  if (status.authenticated) {
    authPanel.hidden = true;
    dashboard.hidden = false;
    logout.hidden = false;
    await refreshSnapshot();
    return;
  }

  dashboard.hidden = true;
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
}

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

byId("refresh").addEventListener("click", refreshSnapshot);
updateAuthView().catch(() => setAuthError("The authentication service is unavailable."));
