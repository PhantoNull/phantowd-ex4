// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

// Manual caller-supplied coherent policy review; no store or activation route.
const iscsiPreviewPath = "/api/v1/iscsi/preview";
const iscsiPreviewState = { operation: null };
const iscsiDraftFields = Object.freeze(["mode", "target-id", "name", "volume", "path", "capacity", "block-size", "allocation", "access", "initiator", "auth", "chap-user", "secret-ref", "target-user", "target-secret-ref"]);
const iscsiDraftDefaults = Object.freeze({ mode: "new-target", "block-size": "512", allocation: "sparse", access: "ro", auth: "chap" });
const iscsiEditFields = Object.freeze(["mode", "target-id", "name", "state", "lun-id", "initiator", "access"]);

function retireISCSIPreview(clearInput = false) {
  const operation = iscsiPreviewState.operation;
  iscsiPreviewState.operation = null;
  operation?.controller.abort();
  if (operation) clearTimeout(operation.timer);
  byId("iscsi-submit").disabled = false;
  byId("iscsi-submit").removeAttribute("aria-busy");
  byId("iscsi-draft-add").disabled = false;
  byId("iscsi-draft-add").removeAttribute("aria-busy");
  byId("iscsi-draft-fields").disabled = false;
  byId("iscsi-edit-submit").disabled = false;
  byId("iscsi-edit-submit").removeAttribute("aria-busy");
  byId("iscsi-edit-fields").disabled = false;
  byId("iscsi-result").hidden = true;
  byId("iscsi-result").replaceChildren();
  if (clearInput) {
    byId("iscsi-document").value = "";
    for (const field of iscsiDraftFields) byId(`iscsi-draft-${field}`).value = iscsiDraftDefaults[field] ?? "";
    for (const field of iscsiEditFields) byId(`iscsi-edit-${field}`).value = "";
  }
  setText("iscsi-status", "No current preview. Nothing was saved or activated.");
}

function clearISCSIPreview() { retireISCSIPreview(true); }

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
      !Array.isArray(fs?.shares?.volumes) || !fs?.nfs || p.targets.length > 16 || p.backings.length >= 64) invalid();
  for (const field of iscsiDraftFields) if (typeof fields[field] !== "string" || fields[field].length > 1024 || /[\u0000-\u001f\u007f]/.test(fields[field])) invalid();
  const bounded = (value, max) => value.length > 0 && value.length <= max;
  const identifier = value => /^[a-z][a-z0-9-]{0,63}$/.test(value);
  const user = value => /^[a-zA-Z0-9._@-]{1,128}$/.test(value);
  if (!["new-target", "existing-target"].includes(fields.mode) ||
      (fields.mode === "new-target" && (fields["target-id"] !== "" || p.targets.length >= 16)) ||
      (fields.mode === "existing-target" && !identifier(fields["target-id"]))) invalid();
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
  const extending = fields.mode === "existing-target";
  const targetID = extending ? fields["target-id"] : unique(p.targets, "target");
  const backingID = unique(p.backings, "backing"), lunID = unique(p.targets.flatMap(t => t.luns), "lun");
  const auth = { mode: fields.auth, initiator_user: fields["chap-user"], initiator_secret_ref: fields["secret-ref"] };
  if (fields.auth === "mutual-chap") { auth.target_user = fields["target-user"]; auth.target_secret_ref = fields["target-secret-ref"]; }
  const target = extending ? p.targets.find(t => t.id === targetID) : { id: targetID, name: fields.name, state: "disabled", luns: [], initiators: [] };
  if (!target || target.state !== "disabled" || target.name !== fields.name || !Array.isArray(target.luns) || target.luns.length >= 16 || !Array.isArray(target.initiators)) invalid();
  let peer = target.initiators.find(p => p.name === fields.initiator);
  if (peer) {
    // Reusing an initiator never edits credentials or changes older grants.
    if (!Array.isArray(peer.grants) || peer.grants.length >= 16 || ["mode", "initiator_user", "initiator_secret_ref", "target_user", "target_secret_ref"].some(k => (peer.authentication?.[k] ?? "") !== (auth[k] ?? ""))) invalid();
  } else {
    if (target.initiators.length >= 32) invalid();
    peer = { name: fields.initiator, authentication: auth, grants: [] };
    target.initiators.push(peer);
  }
  let number = 0;
  while (number <= 16 && target.luns.some(l => l.number === number)) number++;
  if (number > 16) invalid();
  target.luns.push({ id: lunID, number, backing_id: backingID, access: fields.access });
  peer.grants.push({ lun_id: lunID, access: fields.access });
  p.backings.push({ id: backingID, volume_id: fields.volume, relative_path: fields.path, capacity_bytes: capacity, block_size: block, allocation: fields.allocation });
  if (!extending) p.targets.push(target);
  c.revision++;
  fs.revision = fs.shares.revision = fs.nfs.revision = fs.nfs.volume_revision = p.revision = p.volume_revision = c.revision;
  const candidate = JSON.stringify(c);
  if (new TextEncoder().encode(candidate).byteLength > 656128) invalid();
  return { text: candidate, revision: String(c.revision), targetID, lunID, backingID, initiator: fields.initiator, access: fields.access, targets: p.targets.length, backings: p.backings.length };
}

// Compare the entire public projection, not only the selected changed entry.
// SecretRefs remain in the submitted policy; the reply never exposes them.
function iscsiEditProjection(value, policy = false) {
  const p = policy ? value.iscsi : value;
  return { revision: String(value.revision), smb_definitions: policy ? value.file_services.shares.shares.length : value.smb_definitions,
    nfs_definitions: policy ? value.file_services.nfs.exports.length : value.nfs_definitions,
    backings: p.backings.map(b => ({ id: b.id, volume_id: b.volume_id, relative_path: b.relative_path,
      capacity_bytes: String(b.capacity_bytes), block_size: b.block_size, allocation: b.allocation })),
    targets: p.targets.map(t => ({ id: t.id, name: t.name, desired_state: policy ? t.state : t.desired_state,
      luns: t.luns.map(l => ({ id: l.id, number: l.number, backing_id: l.backing_id, access: l.access })),
      initiators: t.initiators.map(p => ({ name: p.name, desired_authentication: policy ? p.authentication.mode : p.desired_authentication,
        grants: p.grants.map(g => ({ lun_id: g.lun_id, access: g.access })) })) })) };
}

// One scoped desired-state edit. Like additions, the exact ORIGINAL text must
// pass the existing strict server decoder before this candidate is submitted.
function buildISCSIEdit(text, fields) {
  const invalid = () => { throw new Error("Invalid guided iSCSI edit"); };
  const c = JSON.parse(text, (_key, value) => {
    if (typeof value === "number" && !Number.isSafeInteger(value)) invalid();
    return value;
  });
  const p = c?.iscsi, fs = c?.file_services;
  if (c?.format !== "phantowd-nas-service-config" || c.schema_version !== 1 || !Number.isSafeInteger(c.revision) || c.revision < 1 ||
      !Number.isSafeInteger(c.revision + 1) || !Array.isArray(p?.targets) || p.targets.length > 16 ||
      !Array.isArray(p?.backings) || p.backings.length > 64 || !fs?.shares || !fs?.nfs) invalid();
  for (const key of iscsiEditFields) if (typeof fields[key] !== "string" || fields[key].length > 1024 || /[\u0000-\u001f\u007f]/.test(fields[key])) invalid();
  const selected = p.targets.filter(t => t.id === fields["target-id"] && t.name === fields.name);
  if (selected.length !== 1 || !["target-state", "lun-access", "grant-access"].includes(fields.mode)) invalid();
  const target = selected[0];
  if (fields.mode === "target-state") {
    if (!["enabled", "disabled"].includes(fields.state) || target.state === fields.state) invalid();
    target.state = fields.state;
  } else {
    if (target.state !== "disabled" || !["ro", "rw"].includes(fields.access)) invalid();
    const luns = target.luns.filter(l => l.id === fields["lun-id"]);
    if (luns.length !== 1) invalid();
    const lun = luns[0];
    if (fields.mode === "lun-access") {
      // Never silently downgrade grants. Request those edits explicitly first.
      if (lun.access === fields.access || (fields.access === "ro" && target.initiators.some(p => p.grants.some(g => g.lun_id === lun.id && g.access === "rw")))) invalid();
      lun.access = fields.access;
    } else {
      const peers = target.initiators.filter(p => p.name === fields.initiator);
      if (peers.length !== 1 || (lun.access === "ro" && fields.access === "rw")) invalid();
      const grants = peers[0].grants.filter(g => g.lun_id === lun.id);
      if (grants.length !== 1 || grants[0].access === fields.access) invalid();
      grants[0].access = fields.access;
    }
  }
  c.revision++;
  fs.revision = fs.shares.revision = fs.nfs.revision = fs.nfs.volume_revision = p.revision = p.volume_revision = c.revision;
  const candidate = JSON.stringify(c);
  if (new TextEncoder().encode(candidate).byteLength > 656128) invalid();
  return { text: candidate, expected: iscsiEditProjection(c, true) };
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
    try { candidate = draft === "edit" ? buildISCSIEdit(text, Object.fromEntries(iscsiEditFields.map(key => [key, byId(`iscsi-edit-${key}`).value]))) :
      buildISCSIDraft(text, Object.fromEntries(iscsiDraftFields.map(field => [field, byId(`iscsi-draft-${field}`).value]))); }
    catch { setText("iscsi-status", "Guided draft refused. Check the complete policy, exact safe integers and proposed fields. The original text is unchanged; nothing was sent."); return; }
  }
  const operation = { controller: new AbortController(), timer: null };
  iscsiPreviewState.operation = operation;
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
  byId("iscsi-edit-submit").disabled = true; byId("iscsi-edit-submit").setAttribute("aria-busy", "true");
  byId("iscsi-edit-fields").disabled = true;
  setText("iscsi-status", "Validating submitted definitions only…");
  operation.timer = setTimeout(() => operation.controller.abort(), 10000);
  let abort;
  try {
    const work = async () => {
      const response = await request("/api/v1/auth/session", { headers: { Accept: "application/json" } });
      const session = await readAdministrativeJSON(response, "/api/v1/auth/session", signal);
      ensureCurrent();
      if (typeof session.csrf_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)) throw new Error("Session unavailable");
      const review = async body => {
        const preview = await request(iscsiPreviewPath, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": session.csrf_token }, body });
        const value = await readAdministrativeJSON(preview, iscsiPreviewPath, signal, "POST");
        ensureCurrent();
        return validateISCSIPreview(value);
      };
      let value = await review(text);
      if (candidate) {
        value = await review(candidate.text);
        if (draft === "edit") {
          if (JSON.stringify(iscsiEditProjection(value)) !== JSON.stringify(candidate.expected)) throw new Error("Edit preview mismatch");
        } else {
          const target = value.targets.find(t => t.id === candidate.targetID);
          if (value.revision !== candidate.revision || value.targets.length !== candidate.targets || value.backings.length !== candidate.backings ||
            !target || target.desired_state !== "disabled" || !target.luns.some(l => l.id === candidate.lunID && l.backing_id === candidate.backingID && l.access === candidate.access) ||
            !target.initiators.some(p => p.name === candidate.initiator && p.grants.some(g => g.lun_id === candidate.lunID && g.access === candidate.access))) throw new Error("Draft preview mismatch");
        }
      }
      renderISCSIPreview(value);
      if (candidate) byId("iscsi-document").value = candidate.text;
      setText("iscsi-status", draft === "edit" ? "Desired iSCSI edit staged in this draft only. No target was started or stopped, no session revoked, and nothing was saved or opened." : candidate ? "Disabled target/LUN change staged in this draft only. Nothing was saved, created, opened or activated." : "Desired definitions reviewed. Nothing was saved, opened or activated.");
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
      byId("iscsi-edit-submit").disabled = false; byId("iscsi-edit-submit").removeAttribute("aria-busy");
      byId("iscsi-edit-fields").disabled = false;
    }
  }
}

byId("iscsi-form").addEventListener("submit", submitISCSIPreview);
byId("iscsi-document").addEventListener("input", () => retireISCSIPreview());
byId("iscsi-clear").addEventListener("click", clearISCSIPreview);
byId("iscsi-draft-add").addEventListener("click", event => submitISCSIPreview(event, true));
for (const field of iscsiDraftFields) byId(`iscsi-draft-${field}`).addEventListener("input", () => retireISCSIPreview());
byId("iscsi-edit-submit").addEventListener("click", event => submitISCSIPreview(event, "edit"));
for (const key of iscsiEditFields) byId(`iscsi-edit-${key}`).addEventListener("input", () => retireISCSIPreview());
