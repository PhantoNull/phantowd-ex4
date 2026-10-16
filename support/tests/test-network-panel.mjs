// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

import assert from "node:assert/strict";

export function networkPolicyFixture() {
  const family = (mode) => ({ mode, addresses: [], default_route: false, metric: 0 });
  return { format: "phantowd-network-policy", schema_version: 1, revision: 1, hostname: "nas-example",
    interfaces: [
      { slot: "lan-1", ipv4: { mode: "static", addresses: ["192.0.2.10/16"], default_route: true, gateway: "192.0.2.1", metric: 100 },
        ipv6: { mode: "static", addresses: ["2001:db8:1::10/64"], default_route: true, gateway: "fe80::1", metric: 100 } },
      { slot: "lan-2", ipv4: family("dhcp"), ipv6: family("auto") },
    ], routes: [{ slot: "lan-1", destination: "198.51.100.0/24", gateway: "192.0.2.2", metric: 300 }],
    dns: { mode: "automatic", source: "lan-2", servers: [], search_domains: ["example.invalid"] } };
}

export function networkPreviewFixture() {
  const c = networkPolicyFixture();
  return { ...c, format: "phantowd-desired-network-preview", revision: "18446744073709551615", scope: "submitted-desired-policy-only",
    saved: false, applied: false, interface_binding_validated: false, kernel_state_validated: false, conflicts_validated: false,
    reachability_validated: false, activation_available: false, limitations: ["Fixture-only proposed settings, not live networking."] };
}

const text = element => [element.textContent, ...element.children.map(text)].join(" ");
const turn = () => new Promise(resolve => setImmediate(resolve));

export async function testNetworkPanel(createHarness, jsonResponse, snapshotResponse) {
  const path = "/api/v1/network/preview", token = "a".repeat(43);
  const common = route => route === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    route === "/api/v1/auth/session" ? jsonResponse({ csrf_token: token }) : snapshotResponse(route);
  const source = JSON.stringify(networkPolicyFixture());
  const h = await createHarness(async route => route === path ? jsonResponse(networkPreviewFixture()) : common(route));
  assert.equal(h.requests.filter(r => r.path === path).length, 0, "never automatic");
  h.elements["network-document"].value = source;
  await h.context.submitNetworkPreview({ preventDefault() {} });
  assert.equal(h.elements["network-result"].hidden, false);
  const post = h.requests.filter(r => r.path === path);
  assert.equal(post.length, 1); assert.equal(post[0].options.method, "POST");
  assert.equal(post[0].options.body, source); assert.equal(post[0].options.headers["X-PhantoWD-CSRF"], token);
  const displayed = text(h.elements["network-result"]);
  assert.match(displayed, /18446744073709551615/); assert.match(displayed, /192\.0\.2\.10\/16/);
  assert.match(displayed, /2001:db8:1::10\/64/); assert.match(displayed, /fe80::1/);
  assert.match(displayed, /NOT SAVED \/ NOT APPLIED/); assert.match(displayed, /not a physical port mapping/);
  assert.match(displayed, /automatic from lan-2/); assert.match(displayed, /not checked/);
  const dynamic = networkPreviewFixture(); dynamic.routes = [];
  h.context.renderNetworkPreview(dynamic);
  assert.match(text(h.elements["network-result"]), /Explicit empty.*live routes were not read/);
  const manual = networkPreviewFixture(); manual.dns = { mode: "manual", servers: ["192.0.2.53"], search_domains: [] };
  manual.unknown_private = "PRIVATE-UNKNOWN"; manual.limitations = ["<img onerror=unsafe>"];
  h.context.renderNetworkPreview(manual);
  assert.match(text(h.elements["network-result"]), /Desired DNS servers: 192\.0\.2\.53/);
  assert.match(text(h.elements["network-result"]), /<img onerror=unsafe>/);
  assert.doesNotMatch(text(h.elements["network-result"]), /PRIVATE-UNKNOWN/);
  for (const change of [
    p => { p.schema_version = 2; }, p => { p.scope = "live"; }, p => { p.format = "phantowd-network-policy"; },
    p => { p.revision = 1; }, p => { p.revision = "01"; }, p => { p.revision = "18446744073709551616"; },
    ...["saved", "applied", "interface_binding_validated", "kernel_state_validated", "conflicts_validated", "reachability_validated", "activation_available"].flatMap(k => [
      p => { p[k] = true; }, p => { delete p[k]; },
    ]),
    p => { p.interfaces = []; }, p => { p.interfaces.push(p.interfaces[0]); }, p => { p.interfaces[1].slot = "lan-1"; },
    p => { p.interfaces[0].slot = "eth0"; }, p => { p.interfaces[0].ipv4.addresses = []; },
    p => { p.interfaces[1].ipv4.addresses = ["192.0.2.1/24"]; }, p => { p.interfaces[0].ipv4.metric = 0; },
    p => { p.interfaces[0].ipv6.gateway = null; }, p => { p.interfaces[0].ipv4.mode = "auto"; },
    p => { p.routes = null; }, p => { p.routes[0].slot = "eth0"; }, p => { p.routes[0].metric = 65536; },
    p => { p.dns.source = "eth0"; }, p => { p.dns.servers = ["192.0.2.53"]; },
    p => { p.limitations = []; }, p => { p.hostname = ""; },
  ]) {
    const p = networkPreviewFixture(); change(p);
    assert.throws(() => h.context.validateNetworkPreview(p), /Unverified network preview/);
  }
  for (const input of ["", "x".repeat(16385), "é".repeat(10000)]) {
    const before = h.requests.length; h.elements["network-document"].value = input;
    await h.context.submitNetworkPreview(); assert.equal(h.requests.length, before);
  }
  h.elements["network-document"].listeners.get("input")();
  assert.equal(h.elements["network-result"].hidden, true);
  for (const stage of ["session-headers", "session-body", "preview-headers", "preview-body"]) {
    const timers = new Map(); let timerID = 0, release, entered = false;
    const blocked = new Promise(resolve => { release = resolve; });
    const body = value => ({ ok: true, status: 200, body: { getReader: () => ({
      read: async () => { await blocked; return { value: new TextEncoder().encode(JSON.stringify(value)), done: false }; },
      cancel: async () => {}, releaseLock() {},
    }) } });
    const b = await createHarness(async route => {
      if (route === "/api/v1/auth/session") {
        if (stage === "session-headers") { entered = true; await blocked; }
        if (stage === "session-body") { entered = true; return body({ csrf_token: token }); }
      }
      if (route === path) {
        entered = true;
        if (stage === "preview-headers") await blocked;
        if (stage === "preview-body") return body(networkPreviewFixture());
        return jsonResponse(networkPreviewFixture());
      }
      return common(route);
    }, { setTimeout(callback, delay) { const id = ++timerID; timers.set(id, { callback, delay }); return id; }, clearTimeout(id) { timers.delete(id); } });
    b.elements["network-document"].value = source;
    const pending = b.context.submitNetworkPreview(); await turn();
    assert.equal(entered, true, stage);
    const count = b.requests.length;
    await b.context.submitNetworkPreview(); assert.equal(b.requests.length, count);
    assert.equal(timers.size, 1); const timer = [...timers.values()][0]; assert.equal(timer.delay, 10000); timer.callback();
    await pending;
    assert.equal(b.elements["network-submit"].disabled, false); assert.equal(b.elements["network-result"].hidden, true);
    assert.match(b.elements["network-status"].textContent, /timed out/);
    release(); await turn(); await turn();
    assert.equal(b.requests.length, count); assert.equal(b.elements["network-result"].hidden, true);
  }
  for (const retire of ["edit", "logout"]) {
    let release, first = true;
    const blocked = new Promise(resolve => { release = resolve; });
    const b = await createHarness(async route => {
      if (route === path) {
        if (first) { first = false; await blocked; return jsonResponse({}, 401); }
        return jsonResponse(networkPreviewFixture());
      }
      return common(route);
    });
    b.elements["network-document"].value = source;
    const old = b.context.submitNetworkPreview(); await turn();
    if (retire === "edit") b.elements["network-document"].listeners.get("input")();
    else b.context.showAuthUnavailable();
    await old;
    b.elements["dashboard-content"].hidden = false;
    b.elements["network-document"].value = source; await b.context.submitNetworkPreview();
    release(); await turn(); await turn();
    assert.equal(b.elements["network-result"].hidden, false); assert.equal(b.elements["dashboard-content"].hidden, false);
  }
  const lost = await createHarness(async route => route === path ? jsonResponse({ error: "PRIVATE" }, 401) : common(route));
  lost.elements["network-document"].value = source; await lost.context.submitNetworkPreview();
  assert.equal(lost.elements["network-document"].value, ""); assert.equal(lost.elements["network-result"].hidden, true);
  assert.equal(lost.elements["dashboard-content"].hidden, true);
  assert.doesNotMatch(lost.elements["network-status"].textContent, /PRIVATE/);
  const exact = new Response('{"ok":true}' + " ".repeat(32768 - 11));
  assert.equal((await h.context.readAdministrativeJSON(exact, path, undefined, "POST")).ok, true);
  await assert.rejects(h.context.readAdministrativeJSON(new Response(new Uint8Array(32769)), path, undefined, "POST"), /administrative body unavailable/);
  await assert.rejects(h.context.readAdministrativeJSON(new Response("{}"), path), /administrative path unavailable/);
  h.context.clearNetworkPreview(); assert.equal(h.elements["network-document"].value, ""); assert.equal(h.elements["network-result"].children.length, 0);
  process.stdout.write("Network panel controls passed: manual-only=true desired-not-observed=true exact-revision=true byte-bounds=true deadlines=4 retired401-safe=true private-clear=true apply=false.\n");
}
