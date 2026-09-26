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
  byId("service-editor").disabled = serviceState.busy || serviceState.baseline === undefined || serviceState.attempted !== null;
  byId("service-edit-preview").disabled = byId("service-editor").disabled;
}

function invalidateServiceDraft() {
  if (serviceState.candidate !== null) setText("service-status", "Draft changed. Preview the change again before saving.");
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
  renderServiceTargets(null);
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

// Each operation edits one explicitly identified object/rule. References are
// retained even when unused: removing policy is not account/volume deletion.
function buildServiceEdit(baseline, action, target, values) {
  if (baseline === undefined) throw new Error("Load current configuration first.");
  const c = baseline === null ? {
    format: "phantowd-file-service-config", schema_version: 1, revision: 0,
    shares: { format: "phantowd-share-config", schema_version: 1, revision: 0, volumes: [], users: [], shares: [] },
    nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 0, volume_revision: 0, exports: [] },
  } : policyCopy(baseline);
  const next = c.revision + 1;
  if (!Number.isSafeInteger(next)) throw new Error("Revision exceeds browser precision.");
  const unique = (items, prefix) => {
    for (let i = 1; i <= 129; i++) if (!items.some((item) => item.id === `${prefix}-${i}`)) return `${prefix}-${i}`;
    throw new Error("No identifier available.");
  };
  const volume = () => {
    let v = c.shares.volumes.find((v) => v.filesystem_uuid === values.uuid);
    if (!v) { v = { id: unique(c.shares.volumes, "volume"), filesystem_uuid: values.uuid }; c.shares.volumes.push(v); }
    return v.id;
  };
  const client = () => {
    const number = (key) => {
      if (!/^[1-9][0-9]*$/.test(values[key]) || Number(values[key]) >= 4294967295) throw new Error("Anonymous IDs must be whole numbers from 1 to 4294967294.");
      return Number(values[key]);
    };
    return { network: values.network, access: values["nfs-access"], squash: values.squash,
      anonymous_uid: number("uid"), anonymous_gid: number("gid"), security: values.security };
  };
  let summary;
  if (action === "nfs-add") {
    if (c.nfs.exports.some((e) => e.id === values["export-id"])) throw new Error("NFS export UUID already exists.");
    c.nfs.exports.push({ id: values["export-id"], volume_id: volume(), relative_path: values.path, clients: [client()] });
    summary = `Add independent NFS export ${values["export-id"]} at ${values.path}; SMB is unchanged.`;
  } else if (action.startsWith("smb-") && target.startsWith("smb:")) {
    const s = c.shares.shares.find((s) => s.id === target.slice(4));
    if (!s) throw new Error("Selected SMB share is no longer in the loaded revision.");
    if (action === "smb-properties") {
      if (c.shares.shares.some((other) => other.id !== s.id && other.name.toLowerCase() === values.name.toLowerCase())) throw new Error("Share name already exists.");
      summary = `Change SMB ${s.name}: name to ${values.name}, folder to ${values.path}, filesystem to ${values.uuid}. Retain all ${s.grants.length} grants; NFS paths and rules are unchanged.`;
      s.name = values.name; s.relative_path = values.path; s.volume_id = volume();
    } else if (action === "smb-remove") {
      c.shares.shares = c.shares.shares.filter((other) => other.id !== s.id);
      summary = `Remove only SMB share ${s.name} (${s.id}). All NFS exports and data remain unchanged; this does not revoke NFS access.`;
    } else if (action === "smb-grant-upsert" || action === "smb-grant-remove") {
      let user = c.shares.users.find((u) => u.name === values.user);
      if (!user && action === "smb-grant-upsert") {
        user = { id: unique(c.shares.users, "user"), name: values.user }; c.shares.users.push(user);
      }
      const existing = user && s.grants.find((g) => g.user_id === user.id);
      if (action === "smb-grant-remove") {
        if (!existing) throw new Error("That user has no grant on the selected share.");
        if (s.grants.length === 1) throw new Error("Cannot remove the last grant. Remove the share definition explicitly instead.");
        s.grants = s.grants.filter((g) => g.user_id !== user.id);
        summary = `Remove ${values.user}'s SMB grant on ${s.name}. Other grants, users and NFS access are retained.`;
      } else {
        if (existing) existing.access = values["smb-access"];
        else s.grants.push({ user_id: user.id, access: values["smb-access"] });
        summary = `Set ${values.user}'s grant on ${s.name} to ${values["smb-access"]}. All other grants are retained; no account is provisioned and NFS is unchanged.`;
      }
    } else throw new Error("Unsupported SMB operation.");
  } else if (action.startsWith("nfs-") && target.startsWith("nfs:")) {
    const e = c.nfs.exports.find((e) => e.id === target.slice(4));
    if (!e) throw new Error("Selected NFS export is no longer in the loaded revision.");
    if (action === "nfs-properties") {
      summary = `Change NFS export ${e.id} to ${values.path} on filesystem ${values.uuid}. Retain export UUID and all ${e.clients.length} client rules. SMB paths are unchanged; no files are moved.`;
      e.volume_id = volume(); e.relative_path = values.path;
    } else if (action === "nfs-remove") {
      c.nfs.exports = c.nfs.exports.filter((other) => other.id !== e.id);
      summary = `Remove only NFS export ${e.id}. SMB definitions, volumes and files are retained.`;
    } else if (action === "nfs-client-upsert" || action === "nfs-client-remove") {
      const index = e.clients.findIndex((rule) => rule.network === values.network);
      if (action === "nfs-client-remove") {
        if (index < 0) throw new Error("That exact CIDR has no rule on this export.");
        if (e.clients.length === 1) throw new Error("Cannot remove the last client rule. Remove the export explicitly instead.");
        e.clients.splice(index, 1);
        summary = `Remove only client ${values.network} from NFS export ${e.id}. Other clients and SMB grants are retained.`;
      } else {
        if (index < 0) e.clients.push(client()); else e.clients[index] = client();
        summary = `Set NFS client ${values.network} on export ${e.id} to ${values["nfs-access"]}, squash=${values.squash}, anonymous=${values.uid}:${values.gid}, security=${values.security}. Other clients and SMB grants are retained.`;
      }
    } else throw new Error("Unsupported NFS operation.");
  } else throw new Error("Choose the matching saved SMB share or NFS export for this operation.");
  // Refuse accidental empty transactions. Revisions are compared before advance.
  if (baseline !== null && sameServiceDocument(c, baseline)) throw new Error("No policy change to save.");
  c.revision = c.shares.revision = c.nfs.revision = c.nfs.volume_revision = next;
  if (new TextEncoder().encode(JSON.stringify(c)).length > 524800) throw new Error("Combined configuration exceeds the request limit.");
  return { configuration: c, summary };
}

function serviceOptions(id, prompt, entries) {
  const option = (value, label) => { const node = document.createElement("option"); node.value = value; node.textContent = label; return node; };
  byId(id).replaceChildren(option("", prompt), ...entries.map(([value, label]) => option(value, label)));
  byId(id).value = "";
}

function renderServiceTargets(c) {
  serviceOptions("service-target", "Choose a saved item", c === null ? [] : [
    ...c.shares.shares.map((s) => [`smb:${s.id}`, `SMB: ${s.name} (${s.id})`]),
    ...c.nfs.exports.map((e) => [`nfs:${e.id}`, `NFS: ${e.relative_path} (${e.id})`]),
  ]);
  serviceOptions("service-member", "Choose an existing access rule", []);
}

function selectServiceTarget() {
  invalidatePolicyPreview();
  const c = serviceState.baseline, target = byId("service-target").value;
  serviceOptions("service-member", "Choose an existing access rule", []);
  if (!c) return;
  const smb = target.startsWith("smb:");
  const item = (smb ? c.shares.shares : c.nfs.exports).find((item) => item.id === target.slice(4));
  if (!item) return;
  byId("policy-uuid").value = c.shares.volumes.find((v) => v.id === item.volume_id).filesystem_uuid;
  byId("policy-path").value = item.relative_path;
  byId("service-action").value = smb ? "smb-properties" : "nfs-properties";
  byId("policy-nfs-enabled").value = smb ? "off" : "on";
  if (smb) {
    byId("policy-name").value = item.name;
    byId("policy-user").value = "";
    serviceOptions("service-member", "Choose a user grant", item.grants.map((g) => [g.user_id, `${c.shares.users.find((u) => u.id === g.user_id).name}: ${g.access}`]));
  } else {
    byId("policy-export-id").value = item.id;
    byId("policy-network").value = "";
    serviceOptions("service-member", "Choose a client rule", item.clients.map((rule) => [rule.network, `${rule.network}: ${rule.access}`]));
  }
  syncPolicyNFS();
  setText("service-status", "Saved fields copied into the form. Select an operation and preview the complete change; nothing was saved.");
}

function selectServiceMember() {
  invalidatePolicyPreview();
  const c = serviceState.baseline, target = byId("service-target").value, member = byId("service-member").value;
  if (!c) return;
  if (target.startsWith("smb:")) {
    const s = c.shares.shares.find((s) => s.id === target.slice(4));
    const grant = s?.grants.find((g) => g.user_id === member);
    if (!grant) return;
    byId("policy-user").value = c.shares.users.find((u) => u.id === member).name;
    byId("policy-smb-access").value = grant.access;
  } else {
    const e = c.nfs.exports.find((e) => e.id === target.slice(4));
    const rule = e?.clients.find((rule) => rule.network === member);
    if (!rule) return;
    for (const [field, value] of Object.entries({ network: rule.network, "nfs-access": rule.access, squash: rule.squash,
      uid: rule.anonymous_uid, gid: rule.anonymous_gid, security: rule.security })) byId(`policy-${field}`).value = String(value);
  }
}

async function prepareServiceEdit() {
  return previewServiceChange(() => buildServiceEdit(serviceState.baseline, byId("service-action").value,
    byId("service-target").value, Object.fromEntries(policyFields.map((field) => [field, byId(`policy-${field}`).value]))));
}

function selectServiceAction() {
  invalidatePolicyPreview();
  byId("policy-nfs-enabled").value = byId("service-action").value.startsWith("nfs-") ? "on" : "off";
  syncPolicyNFS();
}

function showServiceBaseline(c) {
  byId("service-current").hidden = false;
  setText("service-summary", c === null ? "Storage available, but no configuration initialized." :
    `Saved revision ${c.revision}: ${c.shares.shares.length} SMB share(s), ${c.nfs.exports.length} NFS export(s). Desired state only.`);
  setText("service-document", c === null ? "No saved document." : JSON.stringify(c, null, 2));
  renderServiceTargets(c);
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
    renderServiceTargets(null);
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
  return previewServiceChange(() => {
    const c = buildServiceAddition(serviceState.baseline, buildPolicyProposal());
    const addition = c.shares.shares[c.shares.shares.length - 1];
    return { configuration: c, summary: `Add ${addition.name} at ${addition.relative_path}; preserve ${c.shares.shares.length - 1} existing SMB share(s).` };
  });
}

async function previewServiceChange(build) {
  if (serviceState.baseline === undefined || serviceState.attempted !== null) return;
  return serviceOperation(async (request, session) => {
    invalidateServiceDraft();
    setText("service-status", "Validating the complete resulting configuration. No save has been sent.");
    const draftGeneration = policyGeneration;
    const { configuration: c, summary } = build();
    const headers = await session();
    if (draftGeneration !== policyGeneration) { setText("service-status", "Form changed. Preview again before saving."); return; }
    const preview = await request("/api/v1/file-services/preview", { method: "POST", headers, body: JSON.stringify({ shares: c.shares, nfs: c.nfs }) });
    if (draftGeneration !== policyGeneration) { setText("service-status", "Form changed. Preview again before saving."); return; }
    validatePolicyPreview(preview);
    serviceState.candidate = c;
    setText("service-change", `${summary} Save revision ${c.revision}, including ${c.shares.shares.length} SMB share(s) and ${c.nfs.exports.length} NFS export(s). No service activation or file deletion.`);
    setText("service-samba", preview.samba.samba_share_sections || "No SMB sections.");
    setText("service-nfs", preview.nfs.exports_table || "No NFS exports.");
    byId("service-review").hidden = false;
    setText("service-status", "Complete policy preview passed. Review the result, then save explicitly. No service will be activated.");
  });
}

async function saveServiceChange() {
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
