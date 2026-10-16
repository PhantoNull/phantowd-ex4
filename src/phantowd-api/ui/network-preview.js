// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

const networkPreviewPath = "/api/v1/network/preview";
const networkPreviewState = { operation: null };

function retireNetworkPreview(clearInput = false) {
  const operation = networkPreviewState.operation;
  networkPreviewState.operation = null;
  operation?.controller.abort();
  if (operation) clearTimeout(operation.timer);
  byId("network-submit").disabled = false;
  byId("network-submit").removeAttribute("aria-busy");
  byId("network-result").hidden = true;
  byId("network-result").replaceChildren();
  if (clearInput) byId("network-document").value = "";
  setText("network-status", "No current preview. Nothing was saved or applied.");
}

function clearNetworkPreview() { retireNetworkPreview(true); }

function validateNetworkPreview(p) {
  const invalid = () => { throw new Error("Unverified network preview"); };
  const record = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const text = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
  const array = (v, min, max) => Array.isArray(v) && v.length >= min && v.length <= max;
  const metric = v => Number.isSafeInteger(v) && v >= 0 && v <= 65535;
  const decimal = v => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v) && (v.length < 20 || v <= "18446744073709551615");
  if (!record(p) || p.format !== "phantowd-desired-network-preview" || p.schema_version !== 1 || p.scope !== "submitted-desired-policy-only" ||
      !decimal(p.revision) || !text(p.hostname, 63) || !array(p.interfaces, 2, 2) || !array(p.routes, 0, 16) || !record(p.dns) ||
      ["saved", "applied", "interface_binding_validated", "kernel_state_validated", "conflicts_validated", "reachability_validated", "activation_available"].some(k => p[k] !== false) ||
      !array(p.limitations, 1, 6) || !p.limitations.every(v => text(v, 1024))) invalid();
  const slots = new Set();
  for (const port of p.interfaces) {
    if (!record(port) || !["lan-1", "lan-2"].includes(port.slot) || slots.has(port.slot)) invalid();
    slots.add(port.slot);
    for (const [key, dynamic] of [["ipv4", "dhcp"], ["ipv6", "auto"]]) {
      const f = port[key];
      if (!record(f) || !["disabled", dynamic, "static"].includes(f.mode) || !array(f.addresses, f.mode === "static" ? 1 : 0, f.mode === "static" ? 4 : 0) ||
          !f.addresses.every(v => text(v, 64)) || typeof f.default_route !== "boolean" || !metric(f.metric) ||
          f.default_route !== (f.metric !== 0) || (f.gateway !== undefined && !text(f.gateway, 64)) ||
          (f.mode !== "static" && f.gateway !== undefined) ||
          (f.mode === "static" && f.default_route !== (f.gateway !== undefined)) ||
          (f.mode === "disabled" && f.default_route)) invalid();
    }
  }
  if (!p.interfaces.some(port => port.ipv4.mode !== "disabled" || port.ipv6.mode !== "disabled")) invalid();
  for (const r of p.routes) {
    if (!record(r) || !slots.has(r.slot) || !text(r.destination, 64) || !text(r.gateway, 64) || !metric(r.metric) || r.metric === 0) invalid();
  }
  const dns = p.dns;
  if (!["automatic", "manual"].includes(dns.mode) || !array(dns.servers, dns.mode === "manual" ? 1 : 0, dns.mode === "manual" ? 3 : 0) ||
      !dns.servers.every(v => text(v, 64)) || !array(dns.search_domains, 0, 6) || !dns.search_domains.every(v => text(v, 253)) ||
      (dns.mode === "automatic" ? !slots.has(dns.source) : dns.source !== undefined)) invalid();
  // Display shape/consistency only; never a second address parser or apply gate.
  return p;
}

function renderNetworkPreview(value) {
  const p = validateNetworkPreview(value);
  const root = document.createElement("div");
  const add = (parent, tag, text) => { const e = document.createElement(tag); e.textContent = text; parent.append(e); return e; };
  add(root, "h3", `Submitted revision ${p.revision} — desired hostname ${p.hostname}`);
  add(root, "p", "NOT SAVED / NOT APPLIED / PHYSICAL INTERFACES, LIVE STATE, CONFLICTS AND REACHABILITY NOT VERIFIED");
  for (const port of p.interfaces) {
    const card = add(root, "article", ""); card.className = "saved-policy";
    add(card, "h3", `${port.slot} — logical slot, not a physical port mapping`);
    for (const key of ["ipv4", "ipv6"]) {
      const f = port[key];
      add(card, "p", `${key.toUpperCase()}: desired ${f.mode}; ${f.mode === "static" ? f.addresses.join(", ") : "no submitted static addresses"}.`);
      add(card, "p", f.default_route ? `Desired default route: ${f.gateway ?? "dynamic gateway"}, metric ${f.metric}.` : "No desired default route for this family.");
    }
  }
  const routes = add(root, "ul", "");
  if (!p.routes.length) add(routes, "li", "Explicit empty list of additional desired static routes; live routes were not read.");
  for (const r of p.routes) add(routes, "li", `${r.slot}: desired ${r.destination} via ${r.gateway}, metric ${r.metric}.`);
  add(root, "p", p.dns.mode === "automatic" ? `Desired DNS: automatic from ${p.dns.source}; leased servers are not known.` : `Desired DNS servers: ${p.dns.servers.join(", ")}.`);
  add(root, "p", `Desired search domains: ${p.dns.search_domains.length ? p.dns.search_domains.join(", ") : "none"}. Resolver files and DNS reachability were not checked.`);
  const limitations = add(root, "ul", "");
  for (const line of p.limitations) add(limitations, "li", line);
  byId("network-result").replaceChildren(...root.children);
  byId("network-result").hidden = false;
}

async function submitNetworkPreview(event) {
  event?.preventDefault();
  if (networkPreviewState.operation) return;
  retireNetworkPreview();
  const body = byId("network-document").value;
  if (!body.trim() || body.length > 16384 || new TextEncoder().encode(body).byteLength > 16384) {
    setText("network-status", "Provide one complete desired network policy, at most 16384 UTF-8 bytes. Nothing was sent."); return;
  }
  const operation = { controller: new AbortController(), timer: null };
  networkPreviewState.operation = operation;
  const signal = operation.controller.signal;
  const current = () => networkPreviewState.operation === operation && !signal.aborted;
  const canceled = () => { const e = new Error("Network preview canceled"); e.name = "AbortError"; return e; };
  const request = async (path, options = {}) => {
    if (!current()) throw canceled();
    const response = await fetch(path, { ...options, cache: "no-store", credentials: "same-origin", signal });
    if (!current()) { try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {} throw canceled(); }
    if (response.status === 401) { showAuthUnavailable(); throw canceled(); }
    if (!response.ok) { try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {} throw new Error("Preview refused"); }
    return response;
  };
  byId("network-submit").disabled = true; byId("network-submit").setAttribute("aria-busy", "true");
  setText("network-status", "Validating submitted desired settings only…");
  operation.timer = setTimeout(() => operation.controller.abort(), 10000);
  let abort;
  try {
    const work = async () => {
      const response = await request("/api/v1/auth/session", { headers: { Accept: "application/json" } });
      const session = await readAdministrativeJSON(response, "/api/v1/auth/session", signal);
      if (!current()) throw canceled();
      if (typeof session.csrf_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)) throw new Error("Session unavailable");
      const reply = await request(networkPreviewPath, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", "X-PhantoWD-CSRF": session.csrf_token }, body });
      const value = await readAdministrativeJSON(reply, networkPreviewPath, signal, "POST");
      if (!current()) throw canceled();
      renderNetworkPreview(value);
      setText("network-status", "Submitted desired settings validated for review only. Nothing was saved or applied; live networking was not checked.");
    };
    await new Promise((resolve, reject) => {
      abort = () => reject(canceled());
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) { abort(); return; }
      work().then(resolve, reject);
    });
  } catch {
    if (networkPreviewState.operation === operation) {
      byId("network-result").hidden = true; byId("network-result").replaceChildren();
      setText("network-status", signal.aborted ? "Preview timed out. Nothing was saved or applied." : "Network preview could not be verified. Check the complete policy and session, then retry explicitly. Nothing was saved or applied.");
    }
  } finally {
    signal.removeEventListener("abort", abort);
    clearTimeout(operation.timer);
    if (networkPreviewState.operation === operation) {
      networkPreviewState.operation = null;
      byId("network-submit").disabled = false; byId("network-submit").removeAttribute("aria-busy");
    }
  }
}

byId("network-form").addEventListener("submit", submitNetworkPreview);
byId("network-document").addEventListener("input", () => retireNetworkPreview());
byId("network-clear").addEventListener("click", clearNetworkPreview);
