// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

// Desired-policy drafts and explicit shared NAS save review; no target activation.
const iscsiPreviewPath = "/api/v1/iscsi/preview";
const iscsiPreviewState = { operation: null, staged: null, origin: null };
const iscsiDraftFields = Object.freeze(["name", "volume", "path", "capacity", "block-size", "allocation", "access", "initiator", "auth", "chap-user", "secret-ref", "target-user", "target-secret-ref"]);
const iscsiDraftDefaults = Object.freeze({ "block-size": "512", allocation: "sparse", access: "ro", auth: "chap" });

function retireISCSIPreview(clearInput = false) {
  const operation = iscsiPreviewState.operation;
  const staged = iscsiPreviewState.staged;
  iscsiPreviewState.staged = null;
  iscsiPreviewState.operation = null;
  operation?.controller.abort();
  if (operation) clearTimeout(operation.timer);
  byId("iscsi-submit").disabled = false;
  byId("iscsi-submit").removeAttribute("aria-busy");
  byId("iscsi-draft-add").disabled = false;
  byId("iscsi-draft-add").removeAttribute("aria-busy");
  byId("iscsi-draft-fields").disabled = false;
  byId("iscsi-review-save").disabled = true;
  if (staged) { policyGeneration++; invalidateServiceDraft(); }
  if (clearInput || iscsiPreviewState.origin?.text !== byId("iscsi-document").value) iscsiPreviewState.origin = null;
  byId("iscsi-result").hidden = true;
  byId("iscsi-result").replaceChildren();
  if (clearInput) {
    byId("iscsi-document").value = "";
    for (const field of iscsiDraftFields) byId(`iscsi-draft-${field}`).value = iscsiDraftDefaults[field] ?? "";
  }
  setText("iscsi-status", "No current preview. Nothing was saved or activated.");
  syncNASRestoreControls();
}

function clearISCSIPreview() { retireISCSIPreview(true); }

async function loadISCSIPolicy() {
  if (iscsiPreviewState.operation || serviceState.attempted !== null || nasRestoreState.attempted !== null) return;
  return serviceOperation(async (_request, _session, current, signal) => {
    retireISCSIPreview(); policyGeneration++; invalidateServiceDraft();
    const original = byId("iscsi-document").value;
    const operation = { controller: serviceState.controller, timer: null };
    iscsiPreviewState.operation = operation;
    for (const id of ["iscsi-submit", "iscsi-draft-add", "iscsi-draft-fields"]) byId(id).disabled = true;
    syncNASRestoreControls();
    setText("iscsi-status", "Reading saved policy. The draft is replaced only after validation.");
    try {
      const packet = await fetchDocument(nasConfigurationPath, { signal }).catch((failure) => {
        if (failure?.status === 401 || failure?.name === "AbortError") throw failure;
        throw new Error("Saved NAS policy could not be loaded. Existing draft retained.");
      });
      const reply = packet.value;
      if (!current() || iscsiPreviewState.operation !== operation || byId("iscsi-document").value !== original) return;
      if (reply?.schema_version !== 1 || reply.scope !== "stored-desired-nas-policy-only" || reply.saved !== false ||
          reply.applied !== false || reply.activation_available !== false || reply.revision !== reply.configuration?.revision) throw new Error("Saved NAS policy is unavailable. Existing draft retained.");
      nasRestoreEntries(reply.configuration, reply.backing_capacities);
      const text = JSON.stringify(reply.configuration, (_key, value) => {
        if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("Guided loading requires exact safe integers. Use the original backup or manual review; existing draft retained.");
        return value;
      });
      if (new TextEncoder().encode(text).byteLength > 656128) throw new Error("Saved policy exceeds the draft limit. Existing draft retained.");
      iscsiPreviewState.origin = null; byId("iscsi-document").value = text;
      setText("iscsi-status", "Saved policy loaded into the draft. Nothing was changed or activated.");
    } catch (failure) {
      if (iscsiPreviewState.operation === operation && failure?.status === 401) showAuthUnavailable();
      throw failure;
    } finally {
      if (iscsiPreviewState.operation === operation) {
        iscsiPreviewState.operation = null;
        for (const id of ["iscsi-submit", "iscsi-draft-add", "iscsi-draft-fields"]) byId(id).disabled = false;
        syncNASRestoreControls();
      }
    }
  }, false, "iscsi-status");
}

async function reviewISCSIDraftSave() {
  const staged = iscsiPreviewState.staged;
  if (!staged || iscsiPreviewState.operation || nasRestoreState.attempted !== null || serviceState.attempted !== null) return;
  const current = () => iscsiPreviewState.staged === staged && byId("iscsi-document").value === staged.text;
  await previewNASRestoreSource({ current, baseline: JSON.parse(staged.baseline), candidate: JSON.parse(staged.text),
    backup: `{"format":"phantowd-nas-policy-backup","schema_version":1,"configuration":${staged.text}}` });
  if (current() && !byId("nas-restore-review").hidden) {
    setText("iscsi-status", "Review all changes in Saved NAS configuration above, then save explicitly. No target will be activated.");
    byId("nas-restore-review").scrollIntoView?.({ block: "nearest" });
  }
}

// Local draft only. The ORIGINAL exact text must pass the server's strict
// decoder before this normalized candidate can be submitted/published. This
// prevents duplicate/unknown keys from being silently repaired by JSON.parse.
function buildISCSIDraft(text, fields) {
  const invalid = () => { throw new Error("Invalid guided iSCSI draft"); };
  const c = JSON.parse(text, (_key, value) => {
    if (typeof value === "number" && !Number.isSafeInteger(value)) invalid();
    return value;
  });
  const p = c?.iscsi, fs = c?.file_services;
  if (c?.format !== "phantowd-nas-service-config" || c.schema_version !== 1 || !Number.isSafeInteger(c.revision) || c.revision < 1 ||
      !Number.isSafeInteger(c.revision + 1) || !Array.isArray(p?.targets) || !Array.isArray(p?.backings) ||
      !Array.isArray(fs?.shares?.volumes) || !fs?.nfs || p.targets.length >= 16 || p.backings.length >= 64) invalid();
  for (const field of iscsiDraftFields) if (typeof fields[field] !== "string" || fields[field].length > 1024 || /[\u0000-\u001f\u007f]/.test(fields[field])) invalid();
  const bounded = (value, max) => value.length > 0 && value.length <= max;
  const identifier = value => /^[a-z][a-z0-9-]{0,63}$/.test(value);
  const user = value => /^[a-zA-Z0-9._@-]{1,128}$/.test(value);
  if (!bounded(fields.name, 223) || !bounded(fields.initiator, 223) || !identifier(fields.volume) ||
      !fs.shares.volumes.some(v => v.id === fields.volume) || !bounded(fields.path, 1024) || /[\\:]/.test(fields.path) ||
      fields.path.split("/").some(part => !part || part === "." || part === "..") ||
      !/^[1-9][0-9]{0,15}$/.test(fields.capacity) || !["512", "4096"].includes(fields["block-size"]) ||
      !["sparse", "preallocated"].includes(fields.allocation) || !["ro", "rw"].includes(fields.access) ||
      !["chap", "mutual-chap"].includes(fields.auth) || !user(fields["chap-user"]) || !identifier(fields["secret-ref"])) invalid();
  const capacity = Number(fields.capacity), block = Number(fields["block-size"]);
  if (!Number.isSafeInteger(capacity) || capacity < block || capacity % block !== 0 ||
      (fields.auth === "chap" && (fields["target-user"] !== "" || fields["target-secret-ref"] !== "")) ||
      (fields.auth === "mutual-chap" && (!user(fields["target-user"]) || !identifier(fields["target-secret-ref"]) || fields["secret-ref"] === fields["target-secret-ref"]))) invalid();
  const unique = (items, prefix) => {
    for (let i = 1; i <= 65; i++) if (!items.some(item => item.id === `${prefix}-${i}`)) return `${prefix}-${i}`;
    invalid();
  };
  const targetID = unique(p.targets, "target"), backingID = unique(p.backings, "backing"), lunID = unique(p.targets.flatMap(t => t.luns), "lun");
  const auth = { mode: fields.auth, initiator_user: fields["chap-user"], initiator_secret_ref: fields["secret-ref"] };
  if (fields.auth === "mutual-chap") { auth.target_user = fields["target-user"]; auth.target_secret_ref = fields["target-secret-ref"]; }
  p.backings.push({ id: backingID, volume_id: fields.volume, relative_path: fields.path, capacity_bytes: capacity, block_size: block, allocation: fields.allocation });
  p.targets.push({ id: targetID, name: fields.name, state: "disabled", luns: [{ id: lunID, number: 0, backing_id: backingID, access: fields.access }],
    initiators: [{ name: fields.initiator, authentication: auth, grants: [{ lun_id: lunID, access: fields.access }] }] });
  c.revision++;
  fs.revision = fs.shares.revision = fs.nfs.revision = fs.nfs.volume_revision = p.revision = p.volume_revision = c.revision;
  const candidate = JSON.stringify(c);
  if (new TextEncoder().encode(candidate).byteLength > 656128) invalid();
  return { text: candidate, revision: String(c.revision), targetID, targets: p.targets.length, backings: p.backings.length };
}

function validateISCSIPreview(value) {
  const invalid = () => { throw new Error("Unverified iSCSI preview"); };
  const record = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const text = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
  const array = (v, max, min = 0) => Array.isArray(v) && v.length >= min && v.length <= max;
  const decimal = (v, max) => typeof v === "string" && v.length <= max.length && /^[1-9][0-9]*$/.test(v) && (v.length < max.length || v <= max);
  const access = (v) => v === "ro" || v === "rw";
  if (!record(value) || value.format !== "phantowd-desired-iscsi-preview" || value.schema_version !== 2 || value.scope !== "desired-policy-only" ||
      !decimal(value.revision, "18446744073709551615") ||
      ["storage_validated", "credentials_validated", "runtime_validated", "activation_available"].some(key => value[key] !== false) ||
      ![value.smb_definitions, value.nfs_definitions].every(n => Number.isSafeInteger(n) && n >= 0 && n <= 128) ||
      !array(value.backings, 64) || !array(value.targets, 16) || !array(value.limitations, 8, 1) || !value.limitations.every(v => text(v, 1024))) invalid();
  const backings = new Map(), used = new Set(), targetIDs = new Set(), targetNames = new Set(), lunIDs = new Set();
  for (const b of value.backings) {
    if (!record(b) || !text(b.id, 64) || backings.has(b.id) || !text(b.volume_id, 64) || !text(b.relative_path, 1024) ||
        !decimal(b.capacity_bytes, "9223372036854775807") || ![512, 4096].includes(b.block_size) || !["sparse", "preallocated"].includes(b.allocation) ||
        BigInt(b.capacity_bytes) % BigInt(b.block_size) !== 0n ||
        !Number.isSafeInteger(b.smb_path_overlap_count) || b.smb_path_overlap_count < 0 || b.smb_path_overlap_count > value.smb_definitions ||
        !Number.isSafeInteger(b.nfs_path_overlap_count) || b.nfs_path_overlap_count < 0 || b.nfs_path_overlap_count > value.nfs_definitions) invalid();
    backings.set(b.id, b);
  }
  for (const t of value.targets) {
    if (!record(t) || !text(t.id, 64) || targetIDs.has(t.id) || !text(t.name, 223) || targetNames.has(t.name) ||
        !["enabled", "disabled"].includes(t.desired_state) || !array(t.luns, 16, 1) || !array(t.initiators, 32, 1)) invalid();
    targetIDs.add(t.id); targetNames.add(t.name);
    const luns = new Map(), numbers = new Set(), peers = new Set();
    for (const l of t.luns) {
      if (!record(l) || !text(l.id, 64) || lunIDs.has(l.id) || !Number.isSafeInteger(l.number) || l.number < 0 || l.number > 65535 ||
          numbers.has(l.number) || !backings.has(l.backing_id) || used.has(l.backing_id) || !access(l.access)) invalid();
      luns.set(l.id, l); lunIDs.add(l.id); numbers.add(l.number); used.add(l.backing_id);
    }
    for (const p of t.initiators) {
      if (!record(p) || !text(p.name, 223) || peers.has(p.name) || !["chap", "mutual-chap"].includes(p.desired_authentication) || !array(p.grants, 16, 1)) invalid();
      peers.add(p.name);
      const granted = new Set();
      for (const g of p.grants) {
        if (!record(g) || !luns.has(g.lun_id) || granted.has(g.lun_id) || !access(g.access) || (luns.get(g.lun_id).access === "ro" && g.access === "rw")) invalid();
        granted.add(g.lun_id);
      }
    }
  }
  if (used.size !== backings.size) invalid();
  return value; // Display guard only; the server validates the complete policy.
}

function renderISCSIPreview(value) {
  const p = validateISCSIPreview(value);
  const root = document.createElement("div");
  const add = (parent, tag, text) => { const e = document.createElement(tag); e.textContent = text; parent.append(e); return e; };
  add(root, "h3", `Desired revision ${p.revision} — ${p.targets.length} targets, ${p.backings.length} proposed backings`);
  add(root, "p", "NOT SAVED / NOT APPLIED / STORAGE, CREDENTIALS AND RUNTIME NOT VERIFIED");
  add(root, "p", `${p.smb_definitions} SMB and ${p.nfs_definitions} NFS definitions in the submitted revision. Configured path overlap is advisory only, including read-only shares and disabled targets. Actual access and global use are not checked.`);
  add(root, "p", "Zero configured overlaps does not prove isolation: filesystem aliases, external shares and actual use are not inspected.");
  if (p.targets.length === 0) add(root, "p", "Explicit empty desired iSCSI policy. This says nothing about currently running targets.");
  const backings = new Map(p.backings.map(b => [b.id, b]));
  for (const t of p.targets) {
    const card = document.createElement("article"); card.className = "saved-policy"; root.append(card);
    add(card, "h3", t.name);
    add(card, "p", `Target ${t.id}: desired ${t.desired_state}; running state unavailable.`);
    const luns = add(card, "ul", "");
    for (const l of t.luns) {
      const b = backings.get(l.backing_id);
      add(luns, "li", `LUN ${l.number} (${l.id}), ${l.access}; backing ${b.id}, volume ${b.volume_id}, path ${b.relative_path}; ${b.capacity_bytes} bytes, ${b.block_size}-byte blocks, desired ${b.allocation}.`);
      add(luns, "li", `Backing ${b.id}: configured path overlap advisory — ${b.smb_path_overlap_count} SMB share(s), ${b.nfs_path_overlap_count} NFS export(s). ${b.smb_path_overlap_count || b.nfs_path_overlap_count ? "Review potential backing-file exposure before any future activation." : "No lexical overlap in this proposal; not proof of safe use."}`);
    }
    for (const p of t.initiators) {
      const details = document.createElement("details"); card.append(details);
      add(details, "summary", `${p.name} — desired ${p.desired_authentication}, not authenticated or session-verified`);
      const grants = add(details, "ul", "");
      for (const g of p.grants) add(grants, "li", `LUN ${g.lun_id}: desired ${g.access}`);
    }
  }
  const limitations = add(root, "ul", "");
  for (const line of p.limitations) add(limitations, "li", line);
  byId("iscsi-result").replaceChildren(...root.children);
  byId("iscsi-result").hidden = false;
}

async function submitISCSIPreview(event, draft = false) {
  event?.preventDefault();
  if (iscsiPreviewState.operation) return;
  retireISCSIPreview();
  const text = byId("iscsi-document").value;
  if (text.length > 656128 || !text.trim() || new TextEncoder().encode(text).byteLength > 656128) {
    setText("iscsi-status", "Provide one complete coherent NAS policy, at most 656128 UTF-8 bytes. Nothing was sent."); return;
  }
  let candidate;
  if (draft) {
    try { candidate = buildISCSIDraft(text, Object.fromEntries(iscsiDraftFields.map(field => [field, byId(`iscsi-draft-${field}`).value]))); }
    catch { setText("iscsi-status", "Guided draft refused. Check the complete policy, exact safe integers and proposed fields. The original text is unchanged; nothing was sent."); return; }
  }
  const operation = { controller: new AbortController(), timer: null };
  iscsiPreviewState.operation = operation;
  syncNASRestoreControls();
  const signal = operation.controller.signal;
  const current = () => iscsiPreviewState.operation === operation && !signal.aborted;
  const canceled = () => { const e = new Error("iSCSI preview canceled"); e.name = "AbortError"; return e; };
  const ensureCurrent = () => { if (!current()) throw canceled(); };
  const request = async (path, options = {}) => {
    ensureCurrent();
    const response = await fetch(path, { ...options, cache: "no-store", credentials: "same-origin", signal });
    if (!current()) { try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {} throw canceled(); }
    if (response.status === 401) { showAuthUnavailable(); throw canceled(); }
    if (!response.ok) { try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {} throw new Error("Preview refused"); }
    return response;
  };
  byId("iscsi-submit").disabled = true; byId("iscsi-submit").setAttribute("aria-busy", "true");
  byId("iscsi-draft-add").disabled = true; byId("iscsi-draft-add").setAttribute("aria-busy", "true");
  byId("iscsi-draft-fields").disabled = true;
  setText("iscsi-status", "Validating submitted definitions only…");
  operation.timer = setTimeout(() => operation.controller.abort(), 10000);
  let abort;
  try {
    const work = async () => {
      const response = await request("/api/v1/auth/session", { headers: { Accept: "application/json" } });
      const session = (await readBoundedJSON(response, 4096, signal)).value;
      ensureCurrent();
      if (typeof session.csrf_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)) throw new Error("Session unavailable");
      const review = async body => {
        const preview = await request(iscsiPreviewPath, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": session.csrf_token }, body });
        const value = (await readBoundedJSON(preview, 256 * 1024, signal, 65536)).value;
        ensureCurrent();
        return validateISCSIPreview(value);
      };
      let value = await review(text);
      if (candidate) {
        value = await review(candidate.text);
        if (value.revision !== candidate.revision || value.targets.length !== candidate.targets || value.backings.length !== candidate.backings ||
            !value.targets.some(t => t.id === candidate.targetID && t.desired_state === "disabled")) throw new Error("Draft preview mismatch");
      }
      renderISCSIPreview(value);
      if (candidate) {
        const baseline = iscsiPreviewState.origin?.text === text ? iscsiPreviewState.origin.baseline : text;
        policyGeneration++; invalidateServiceDraft();
        byId("iscsi-document").value = candidate.text;
        iscsiPreviewState.origin = iscsiPreviewState.staged = { baseline, text: candidate.text };
      }
      setText("iscsi-status", candidate ? "Disabled target staged in this draft only. Nothing was saved, created, opened or activated." : "Desired definitions reviewed. Nothing was saved, opened or activated.");
    };
    await new Promise((resolve, reject) => {
      abort = () => reject(canceled());
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) { abort(); return; }
      work().then(resolve, reject);
    });
  } catch {
    if (iscsiPreviewState.operation === operation) {
      byId("iscsi-result").hidden = true; byId("iscsi-result").replaceChildren();
      setText("iscsi-status", signal.aborted ? "Preview timed out. No result is shown; nothing was saved or activated." : "Preview could not be verified. Check the complete coherent policy and session, then retry explicitly. Nothing was saved or activated.");
    }
  } finally {
    signal.removeEventListener("abort", abort);
    clearTimeout(operation.timer);
    if (iscsiPreviewState.operation === operation) {
      iscsiPreviewState.operation = null;
      byId("iscsi-submit").disabled = false; byId("iscsi-submit").removeAttribute("aria-busy");
      byId("iscsi-draft-add").disabled = false; byId("iscsi-draft-add").removeAttribute("aria-busy");
      byId("iscsi-draft-fields").disabled = false;
      syncNASRestoreControls();
    }
  }
}
