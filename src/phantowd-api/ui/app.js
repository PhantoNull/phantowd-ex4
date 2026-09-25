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
    const [systemResult, storageResult] = await Promise.allSettled([
      fetchJSON("/api/v1/system"),
      fetchJSON("/api/v1/storage"),
    ]);
    const results = [systemResult, storageResult];
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
    if (systemCurrent) renderSystem(systemResult.value);
    else clearSystemObservation();
    if (storageCurrent) renderStorage(storageResult.value);
    else clearStorageObservation();

    if (systemCurrent && storageCurrent) {
      status.textContent = "Read-only system and storage observations updated.";
      return;
    }

    const failedDomains = [
      !systemCurrent && "system",
      !storageCurrent && "storage",
    ].filter(Boolean);
    const currentDomains = [
      systemCurrent && "system",
      storageCurrent && "storage",
    ].filter(Boolean);
    const failureSummary = failedDomains.length === 2 ? "System and storage observations unavailable." :
      `${failedDomains[0][0].toUpperCase()}${failedDomains[0].slice(1)} observation unavailable.`;
    const currentSummary = currentDomains.length > 0 ?
      `${currentDomains[0][0].toUpperCase()}${currentDomains[0].slice(1)} observation is current.` :
      "No observations are current.";
    setConnectionState(failedDomains.length === 2 ? "API unavailable" : "Partial snapshot", failedDomains.length === 2 ? "unavailable" : "degraded");
    status.textContent = failedDomains.length === 2 ?
      "System and storage observations unavailable. Current values were cleared." :
      `${currentSummary} ${failureSummary} Failed values were cleared.`;
    error.textContent = failedDomains.length === 2 ?
      "System and storage observations are unavailable. No current values are shown." :
      `${currentSummary} ${failureSummary} No previous ${failedDomains[0]} values are shown.`;
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
    setConnectionState("API unavailable", "unavailable");
    status.textContent = "System and storage observations unavailable. Current values were cleared.";
    error.textContent = "System and storage observations are unavailable. No current values are shown.";
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
updateAuthView().catch(showAuthUnavailable);
