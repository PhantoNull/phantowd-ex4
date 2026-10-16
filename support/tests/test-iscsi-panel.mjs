// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

import assert from "node:assert/strict";

export function iscsiPolicyFixture() {
  return { format: "phantowd-nas-service-config", schema_version: 1, revision: 1,
    file_services: { format: "phantowd-file-service-config", schema_version: 1, revision: 1,
      shares: { format: "phantowd-share-config", schema_version: 1, revision: 1,
        volumes: [{ id: "bulk", filesystem_uuid: "11111111-2222-3333-4444-555555555555" }], users: [], shares: [] },
      nfs: { format: "phantowd-nfs-policy", schema_version: 1, revision: 1, volume_revision: 1, exports: [] } },
    iscsi: { format: "phantowd-iscsi-policy", schema_version: 1, revision: 1, volume_revision: 1,
      backings: [{ id: "backing", volume_id: "bulk", relative_path: "luns/not-opened.img", capacity_bytes: 4096, block_size: 512, allocation: "sparse" }],
      targets: [{ id: "target", name: "iqn.2001-04.com.example:target", state: "enabled",
        luns: [{ id: "lun", number: 0, backing_id: "backing", access: "rw" }],
        initiators: [{ name: "iqn.2001-04.com.example:peer", authentication: { mode: "chap", initiator_user: "private-user", initiator_secret_ref: "private-ref" }, grants: [{ lun_id: "lun", access: "ro" }] }] }] } };
}

export function iscsiPreviewFixture() {
  const c = iscsiPolicyFixture();
  return { format: "phantowd-desired-iscsi-preview", schema_version: 1, scope: "desired-policy-only", revision: "1",
    storage_validated: false, credentials_validated: false, runtime_validated: false, activation_available: false,
    smb_definitions: 0, nfs_definitions: 0,
    backings: c.iscsi.backings.map(b => ({ ...b, capacity_bytes: String(b.capacity_bytes) })),
    targets: c.iscsi.targets.map(t => ({ id: t.id, name: t.name, desired_state: t.state, luns: t.luns,
      initiators: t.initiators.map(p => ({ name: p.name, desired_authentication: p.authentication.mode, grants: p.grants })) })),
    limitations: ["Desired definitions only.", "CHAP does not encrypt data traffic."] };
}

const text = (element) => [element.textContent, ...element.children.map(text)].join(" ");
const turn = () => new Promise(resolve => setImmediate(resolve));

export async function testISCSIPanel(createHarness, jsonResponse, snapshotResponse) {
  const token = "a".repeat(43), path = "/api/v1/iscsi/preview";
  const common = (route) => route === "/api/v1/auth/status" ? jsonResponse({ authenticated: true }) :
    route === "/api/v1/auth/session" ? jsonResponse({ csrf_token: token }) : snapshotResponse(route);
  let output = iscsiPreviewFixture();
  const h = await createHarness(async route => route === path ? jsonResponse(output) : common(route));
  const source = JSON.stringify(iscsiPolicyFixture());
  h.elements["iscsi-document"].value = source;
  await h.context.submitISCSIPreview({ preventDefault() {} });
  assert.equal(h.elements["iscsi-result"].hidden, false);
  const post = h.requests.filter(r => r.path === path);
  assert.equal(post.length, 1); assert.equal(post[0].options.method, "POST");
  assert.equal(post[0].options.body, source); assert.equal(post[0].options.headers["X-PhantoWD-CSRF"], token);
  assert.match(text(h.elements["iscsi-result"]), /LUN 0.*4096 bytes/);
  assert.match(text(h.elements["iscsi-result"]), /desired enabled; running state unavailable/);
  assert.doesNotMatch(text(h.elements["iscsi-result"]), /private-user|private-ref|11111111-2222/);
  output = iscsiPreviewFixture(); output.revision = "18446744073709551615"; output.backings[0].capacity_bytes = "9223372036854771712";
  output.backings[0].relative_path = "luns/<img-onerror>";
  output.unknown_secret = "PRIVATE-UNKNOWN";
  await h.context.submitISCSIPreview();
  assert.match(text(h.elements["iscsi-result"]), /18446744073709551615/);
  assert.match(text(h.elements["iscsi-result"]), /9223372036854771712 bytes/);
  assert.match(text(h.elements["iscsi-result"]), /luns\/<img-onerror>/);
  assert.doesNotMatch(text(h.elements["iscsi-result"]), /PRIVATE-UNKNOWN/);
  const empty = iscsiPreviewFixture(); empty.backings = []; empty.targets = [];
  h.context.renderISCSIPreview(empty);
  assert.match(text(h.elements["iscsi-result"]), /Explicit empty desired iSCSI policy/);
  assert.match(text(h.elements["iscsi-result"]), /nothing about currently running targets/);
  for (const change of [
    p => { p.activation_available = true; }, p => { p.storage_validated = true; },
    p => { p.credentials_validated = true; }, p => { p.runtime_validated = true; },
    p => { p.revision = 1; }, p => { p.revision = "18446744073709551616"; }, p => { p.revision = "01"; },
    p => { p.backings = null; }, p => { p.targets = null; }, p => { p.backings[0].capacity_bytes = 4096; },
    p => { p.backings[0].capacity_bytes = "9223372036854775808"; }, p => { p.backings[0].block_size = 1024; },
    p => { p.targets[0].luns[0].number = 65536; }, p => { p.targets[0].luns[0].backing_id = "foreign"; },
    p => { p.targets[0].initiators[0].grants[0].lun_id = "foreign"; },
    p => { p.targets[0].luns[0].access = "ro"; p.targets[0].initiators[0].grants[0].access = "rw"; },
    p => { p.targets[0].initiators[0].desired_authentication = "none"; }, p => { p.targets[0].desired_state = "running"; },
    p => { p.backings.push({ ...p.backings[0] }); }, p => { p.targets[0].luns.push({ ...p.targets[0].luns[0] }); },
    p => { p.targets = []; }, p => { p.limitations = []; }, p => { p.smb_definitions = 129; },
  ]) {
    const p = iscsiPreviewFixture(); change(p);
    assert.throws(() => h.context.validateISCSIPreview(p), /Unverified iSCSI preview/);
  }
  h.elements["iscsi-document"].listeners.get("input")();
  assert.equal(h.elements["iscsi-result"].hidden, true); assert.equal(h.elements["iscsi-result"].children.length, 0);
  for (const value of ["", "x".repeat(656129), "\u00e9".repeat(400000)]) {
    const before = h.requests.length; h.elements["iscsi-document"].value = value;
    await h.context.submitISCSIPreview(); assert.equal(h.requests.length, before);
  }
  // One whole deadline across session/POST headers and response bodies. A late
  // non-cooperative completion cannot publish or unlock replacement work.
  for (const stage of ["session-headers", "session-body", "preview-headers", "preview-body"]) {
    const timers = new Map(); let timerID = 0, release, entered = false;
    const blocked = new Promise(resolve => { release = resolve; });
    const body = (value) => ({ ok: true, status: 200, body: { getReader: () => ({
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
        if (stage === "preview-body") return body(iscsiPreviewFixture());
        return jsonResponse(iscsiPreviewFixture());
      }
      return common(route);
    }, { setTimeout(callback, delay) { const id = ++timerID; timers.set(id, { callback, delay }); return id; }, clearTimeout(id) { timers.delete(id); } });
    b.elements["iscsi-document"].value = source;
    const operation = b.context.submitISCSIPreview();
    await turn(); assert.equal(entered, true, stage);
    const count = b.requests.length;
    await b.context.submitISCSIPreview(); assert.equal(b.requests.length, count, "single flight");
    assert.equal(timers.size, 1); const timer = [...timers.values()][0]; assert.equal(timer.delay, 10000); timer.callback();
    await operation;
    assert.equal(b.elements["iscsi-submit"].disabled, false); assert.equal(b.elements["iscsi-result"].hidden, true);
    assert.match(b.elements["iscsi-status"].textContent, /timed out/);
    release(); await turn(); await turn();
    assert.equal(b.requests.length, count, "timeout must not send another request");
    assert.equal(b.elements["iscsi-result"].hidden, true);
  }
  // Immediate auth loss clears private text and every old result, without
  // starting an independent status/retry that could replace a newer session.
  const lost = await createHarness(async route => route === path ? jsonResponse({ error: "PRIVATE" }, 401) : common(route));
  lost.elements["iscsi-document"].value = source; await lost.context.submitISCSIPreview();
  assert.equal(lost.elements["iscsi-document"].value, ""); assert.equal(lost.elements["dashboard-content"].hidden, true);
  assert.equal(lost.elements["iscsi-result"].hidden, true); assert.doesNotMatch(lost.elements["iscsi-status"].textContent, /PRIVATE/);
  assert.equal(lost.requests.filter(r => r.path === path).length, 1);
  for (const retire of ["edit", "logout"]) {
    let release, first = true, entered = false;
    const blocked = new Promise(resolve => { release = resolve; });
    const b = await createHarness(async route => {
      if (route === path) {
        if (first) { first = false; entered = true; await blocked; return jsonResponse({}, 401); }
        return jsonResponse(iscsiPreviewFixture());
      }
      return common(route);
    });
    b.elements["iscsi-document"].value = source;
    const old = b.context.submitISCSIPreview(); await turn(); assert.equal(entered, true);
    if (retire === "edit") b.elements["iscsi-document"].listeners.get("input")();
    else {
      b.context.showAuthUnavailable();
      assert.equal(b.elements["iscsi-document"].value, "");
      // Replacement session/view. Old completion has no right to retire it.
      b.elements["dashboard-content"].hidden = false;
    }
    await old;
    b.elements["iscsi-document"].value = source;
    await b.context.submitISCSIPreview();
    assert.equal(b.elements["iscsi-result"].hidden, false);
    release(); await turn(); await turn();
    assert.equal(b.elements["iscsi-result"].hidden, false, retire + ": late401 replaced new preview");
    assert.equal(b.elements["dashboard-content"].hidden, false);
    assert.equal(b.elements["iscsi-document"].value, source);
  }
  const large = new Response(new Uint8Array(262145));
  await assert.rejects(h.context.readAdministrativeJSON(large, path, undefined, "POST"), /administrative body unavailable/);
  await assert.rejects(h.context.readAdministrativeJSON(new Response("{}"), path), /administrative path unavailable/);
  const exact = new Response('{"ok":true}' + " ".repeat(262144 - 11));
  assert.equal((await h.context.readAdministrativeJSON(exact, path, undefined, "POST")).ok, true);
  process.stdout.write("iSCSI panel controls passed: manual-only=true whole-policy=true exact-decimals=true bounds=true deadlines=4 private-clear=true activation=false.\n");
}
