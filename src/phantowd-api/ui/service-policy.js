// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

// Desired-state transactions only. No activation, automatic PUT retry, browser
// persistence or implicit import from the older share-only store.
const servicePath = "/api/v1/file-services/configuration";
const serviceState = { baseline: undefined, candidate: null, attempted: null, busy: false, generation: 0, controller: null };
const policyCopy = (value) => JSON.parse(JSON.stringify(value));

function syncServiceControls() {
  byId("service-load").disabled = serviceState.busy;
  byId("service-prepare").disabled = serviceState.busy || serviceState.baseline === undefined || serviceState.attempted !== null;
  byId("service-save").disabled = serviceState.busy || serviceState.candidate === null || serviceState.attempted !== null;
}

function invalidateServiceDraft() {
  serviceState.candidate = null;
  byId("service-review").hidden = true;
  for (const id of ["service-change", "service-samba", "service-nfs"]) setText(id, "");
  syncServiceControls();
}

function clearServicePolicy() {
  serviceState.generation++;
  serviceState.controller?.abort();
  Object.assign(serviceState, { baseline: undefined, candidate: null, attempted: null, busy: false, controller: null });
  invalidateServiceDraft();
  byId("service-current").hidden = true;
  setText("service-summary", ""); setText("service-document", "");
  setText("service-status", "Not loaded. Reload to learn current saved state; an interrupted save may have committed.");
}

function validateServiceDocument(response) {
  const invalid = () => { throw new Error("Saved configuration has an unsupported or inconsistent format. Save is disabled."); };
  if (response?.schema_version !== 1 || response.scope !== "development-stored-file-service-policy-only" ||
      response.applied !== false || response.runtime_validated !== false || response.activation_available !== false ||
      typeof response.initialized !== "boolean") invalid();
  if (!response.initialized) {
    if (response.configuration !== null) invalid();
    return null;
  }
  const c = response.configuration;
  if (!c || c.format !== "phantowd-file-service-config" || c.schema_version !== 1 ||
      !Number.isSafeInteger(c.revision) || c.revision < 1 || c.shares?.revision !== c.revision ||
      c.nfs?.revision !== c.revision || c.nfs?.volume_revision !== c.revision ||
      c.nfs?.format !== "phantowd-nfs-policy" || c.nfs?.schema_version !== 1 ||
      !Array.isArray(c.nfs.exports) || c.nfs.exports.length > 128 || new TextEncoder().encode(JSON.stringify(c)).length > 524800) invalid();
  const parsed = validateSavedPolicy({ schema_version: 1, scope: "stored-desired-share-policy-only", initialized: true,
    runtime_validated: false, activation_available: false, configuration: c.shares });
  const ids = new Set();
  for (const e of c.nfs.exports) {
    if (!e || typeof e.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(e.id) ||
        ids.has(e.id) || !parsed.volumes.has(e.volume_id) || typeof e.relative_path !== "string" || e.relative_path.length > 512 ||
        !Array.isArray(e.clients) || e.clients.length < 1 || e.clients.length > 64) invalid();
    ids.add(e.id);
    for (const client of e.clients) {
      if (!client || typeof client.network !== "string" || client.network.length > 64 ||
          !["ro", "rw"].includes(client.access) || !["all", "root"].includes(client.squash) ||
          !["sys", "krb5", "krb5i", "krb5p"].includes(client.security) ||
          ![client.anonymous_uid, client.anonymous_gid].every((id) => Number.isInteger(id) && id > 0 && id < 4294967295)) invalid();
    }
  }
  // Display/schema guard only: the server remains the policy validator.
  return c;
}

function buildServiceAddition(baseline, proposal) {
  const next = (baseline?.revision ?? 0) + 1;
  if (!Number.isSafeInteger(next)) throw new Error("Revision exceeds browser precision. Save is disabled.");
  const c = baseline === null ? {
    format: "phantowd-file-service-config", schema_version: 1, revision: next,
    shares: { format: "phantowd-share-config", schema_version: 1, revision: next, volumes: [], users: [], shares: [] },
    nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: next, volume_revision: next, exports: [] },
  } : policyCopy(baseline);
  const p = policyCopy(proposal);
  const unique = (items, prefix) => {
    for (let i = 1; i <= 129; i++) if (!items.some((item) => item.id === `${prefix}-${i}`)) return `${prefix}-${i}`;
    throw new Error("No identifier available.");
  };
  if (c.shares.shares.some((s) => s.name.toLowerCase() === p.shares.shares[0].name.toLowerCase())) {
    throw new Error("A share with this name already exists. This action only adds; it never replaces existing shares.");
  }
  let volume = c.shares.volumes.find((v) => v.filesystem_uuid === p.shares.volumes[0].filesystem_uuid);
  if (!volume) { volume = { ...p.shares.volumes[0], id: unique(c.shares.volumes, "volume") }; c.shares.volumes.push(volume); }
  let user = c.shares.users.find((u) => u.name === p.shares.users[0].name);
  if (!user) { user = { ...p.shares.users[0], id: unique(c.shares.users, "user") }; c.shares.users.push(user); }
  const share = p.shares.shares[0];
  share.id = unique(c.shares.shares, "share"); share.volume_id = volume.id; share.grants[0].user_id = user.id;
  c.shares.shares.push(share);
  for (const e of p.nfs.exports) {
    if (c.nfs.exports.some((existing) => existing.id === e.id)) throw new Error("This NFS export UUID already exists. Choose a distinct export identity.");
    e.volume_id = volume.id; c.nfs.exports.push(e);
  }
  c.revision = c.shares.revision = c.nfs.revision = c.nfs.volume_revision = next;
  if (new TextEncoder().encode(JSON.stringify(c)).length > 524800) throw new Error("Combined configuration exceeds the request limit.");
  return c;
}

// Compare all fields, ignoring object-key order but not array order. Never use
// revision alone as evidence that this client's specific change was committed.
function sameServiceDocument(a, b) {
  const canonical = (value) => Array.isArray(value) ? value.map(canonical) :
    value !== null && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}

function showServiceBaseline(c) {
  byId("service-current").hidden = false;
  setText("service-summary", c === null ? "Storage available, but no configuration initialized." :
    `Saved revision ${c.revision}: ${c.shares.shares.length} SMB share(s), ${c.nfs.exports.length} NFS export(s). Desired state only.`);
  setText("service-document", c === null ? "No saved document." : JSON.stringify(c, null, 2));
}

async function serviceOperation(action) {
  if (serviceState.busy) return;
  serviceState.busy = true;
  const generation = ++serviceState.generation;
  const controller = new AbortController(); serviceState.controller = controller;
  const timeout = setTimeout(() => controller.abort(), 10000);
  syncServiceControls();
  const current = () => generation === serviceState.generation;
  const request = async (path, options = {}) => {
    let response;
    try { response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, signal: controller.signal }); }
    catch (failure) {
      if (failure?.name === "AbortError") throw failure;
      throw new Error("Configuration service could not be reached.");
    }
    if (!current()) throw new Error("superseded");
    if (!response.ok) {
      const failure = new Error(response.status === 401 ? "Session expired. Sign in again." : response.status === 409 ?
        "The saved revision changed. Reload and review before another save." : response.status === 422 ?
        "Policy rejected. Check paths, identities, grants, client networks and existing overlaps." : response.status === 403 ?
        "Session security check failed. Reload and sign in again." : "Configuration service unavailable, disabled or busy. Reload when available.");
      failure.status = response.status; throw failure;
    }
    let body;
    try { body = await response.json(); }
    catch { throw new Error("Configuration service returned an unreadable response."); }
    if (!current()) throw new Error("superseded");
    return body;
  };
  const session = async () => {
    const s = await request("/api/v1/auth/session", { method: "GET", headers: { Accept: "application/json" } });
    if (typeof s.csrf_token !== "string" || !s.csrf_token) throw new Error("Session token unavailable.");
    return { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": s.csrf_token };
  };
  try { await action(request, session); }
  catch (failure) {
    if (!current()) return;
    invalidateServiceDraft();
    if (failure?.status === 401) {
      clearServicePolicy(); byId("dashboard-content").hidden = true;
      try { await updateAuthView({ refresh: false, notice: "Session expired. Reload saved state after signing in; a pending save may have committed." }); }
      catch { showAuthUnavailable(); }
    } else {
      setText("service-status", serviceState.attempted !== null ? failure?.status === 409 ?
        "Revision conflict: this save was refused. Use Load / reconcile, review current state and prepare again; no automatic retry will occur." :
        "Save is not confirmed. It may have committed. Use Load / reconcile; no automatic retry will occur." :
        failure?.name === "AbortError" ? "Request timed out. No save was sent." : failure instanceof Error ? failure.message : "Configuration request failed.");
    }
  } finally {
    clearTimeout(timeout);
    if (current()) { serviceState.busy = false; serviceState.controller = null; syncServiceControls(); }
  }
}

async function loadServicePolicy() {
  return serviceOperation(async (request) => {
    serviceState.baseline = undefined; invalidateServiceDraft();
    byId("service-current").hidden = true; setText("service-document", ""); setText("service-summary", "");
    setText("service-status", "Reading saved state. Previous values were cleared.");
    const c = validateServiceDocument(await request(servicePath, { method: "GET", headers: { Accept: "application/json" } }));
    const pending = serviceState.attempted;
    serviceState.baseline = c; serviceState.attempted = null;
    showServiceBaseline(c);
    setText("service-status", pending !== null ? sameServiceDocument(pending, c) ?
      "The complete attempted configuration is now confirmed saved. No services were activated." :
      "Current saved state differs from the attempted change. It was not retried; review the current state and prepare a new addition if still wanted." :
      "Current desired state loaded. Fill the form, preview an addition, then explicitly save. This does not report running-service state.");
  });
}

async function prepareServiceAddition() {
  if (serviceState.baseline === undefined || serviceState.attempted !== null) return;
  return serviceOperation(async (request, session) => {
    invalidateServiceDraft();
    setText("service-status", "Validating the complete resulting configuration. No save has been sent.");
    const draftGeneration = policyGeneration;
    const c = buildServiceAddition(serviceState.baseline, buildPolicyProposal());
    const headers = await session();
    if (draftGeneration !== policyGeneration) { setText("service-status", "Form changed. Preview again before saving."); return; }
    const preview = await request("/api/v1/file-services/preview", { method: "POST", headers, body: JSON.stringify({ shares: c.shares, nfs: c.nfs }) });
    if (draftGeneration !== policyGeneration) { setText("service-status", "Form changed. Preview again before saving."); return; }
    validatePolicyPreview(preview);
    serviceState.candidate = c;
    const addition = c.shares.shares[c.shares.shares.length - 1];
    setText("service-change", `Add ${addition.name} at ${addition.relative_path}; preserve ${c.shares.shares.length - 1} existing SMB share(s). Save revision ${c.revision}, including ${c.nfs.exports.length} NFS export(s).`);
    setText("service-samba", preview.samba.samba_share_sections || "No SMB sections.");
    setText("service-nfs", preview.nfs.exports_table || "No NFS exports.");
    byId("service-review").hidden = false;
    setText("service-status", "Complete policy preview passed. Review the result, then save explicitly. No service will be activated.");
  });
}

async function saveServiceAddition() {
  if (serviceState.candidate === null || serviceState.attempted !== null) return;
  return serviceOperation(async (request, session) => {
    const c = serviceState.candidate;
    const headers = await session();
    if (serviceState.candidate !== c) { setText("service-status", "Form changed. Preview again before saving."); return; }
    // Once PUT begins any failure may hide a completed commit. Block further
    // saves until an explicit GET reconciles the entire document.
    serviceState.attempted = c; invalidateServiceDraft();
    setText("service-status", "Saving the reviewed revision. A timeout will require reconciliation, not retry.");
    const reply = await request(servicePath, { method: "PUT", headers, body: JSON.stringify(c) });
    if (reply?.schema_version !== 1 || reply.scope !== "development-stored-file-service-policy-only" || reply.revision !== c.revision ||
        reply.saved !== true || reply.applied !== false || reply.runtime_validated !== false || reply.activation_available !== false) {
      throw new Error("Unverified save response.");
    }
    serviceState.baseline = c; serviceState.attempted = null;
    showServiceBaseline(c);
    setText("service-status", `Revision ${c.revision} confirmed saved. No services were activated; runtime access remains unverified.`);
  });
}
