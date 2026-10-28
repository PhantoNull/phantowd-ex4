// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

// Manual caller-supplied coherent policy review; no store or activation route.
const iscsiPreviewPath = "/api/v1/iscsi/preview";
const iscsiPreviewState = { operation: null };

function retireISCSIPreview(clearInput = false) {
  const operation = iscsiPreviewState.operation;
  iscsiPreviewState.operation = null;
  operation?.controller.abort();
  if (operation) clearTimeout(operation.timer);
  byId("iscsi-submit").disabled = false;
  byId("iscsi-submit").removeAttribute("aria-busy");
  byId("iscsi-result").hidden = true;
  byId("iscsi-result").replaceChildren();
  if (clearInput) byId("iscsi-document").value = "";
  setText("iscsi-status", "No current preview. Nothing was saved or activated.");
}

function clearISCSIPreview() { retireISCSIPreview(true); }

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

async function submitISCSIPreview(event) {
  event?.preventDefault();
  if (iscsiPreviewState.operation) return;
  retireISCSIPreview();
  const text = byId("iscsi-document").value;
  if (text.length > 656128 || !text.trim() || new TextEncoder().encode(text).byteLength > 656128) {
    setText("iscsi-status", "Provide one complete coherent NAS policy, at most 656128 UTF-8 bytes. Nothing was sent."); return;
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
  setText("iscsi-status", "Validating submitted definitions only…");
  operation.timer = setTimeout(() => operation.controller.abort(), 10000);
  let abort;
  try {
    const work = async () => {
      const response = await request("/api/v1/auth/session", { headers: { Accept: "application/json" } });
      const session = (await readBoundedJSON(response, 4096, signal)).value;
      ensureCurrent();
      if (typeof session.csrf_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)) throw new Error("Session unavailable");
      const preview = await request(iscsiPreviewPath, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": session.csrf_token }, body: text });
      const value = (await readBoundedJSON(preview, 256 * 1024, signal, 65536)).value;
      ensureCurrent();
      renderISCSIPreview(value);
      setText("iscsi-status", "Desired definitions reviewed. Nothing was saved, opened or activated.");
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
    }
  }
}
