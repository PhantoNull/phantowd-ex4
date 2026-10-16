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
  return iscsiPreviewForPolicy(iscsiPolicyFixture());
}

export function iscsiPreviewForPolicy(c) {
  return { format: "phantowd-desired-iscsi-preview", schema_version: 2, scope: "desired-policy-only", revision: String(c.revision),
    storage_validated: false, credentials_validated: false, runtime_validated: false, activation_available: false,
    smb_definitions: 0, nfs_definitions: 0,
    backings: c.iscsi.backings.map(b => ({ ...b, capacity_bytes: String(b.capacity_bytes), smb_path_overlap_count: 0, nfs_path_overlap_count: 0 })),
    targets: c.iscsi.targets.map(t => ({ id: t.id, name: t.name, desired_state: t.state, luns: t.luns,
      initiators: t.initiators.map(p => ({ name: p.name, desired_authentication: p.authentication.mode, grants: p.grants })) })),
    limitations: ["Desired definitions only.", "CHAP does not encrypt data traffic."] };
}

export function iscsiDraftFieldsFixture() {
  return { mode: "new-target", "target-id": "", name: "iqn.2026-01.org.example:draft", volume: "bulk", path: "luns/draft.img", capacity: "8192", "block-size": "512", allocation: "sparse", access: "ro",
    initiator: "iqn.2026-01.org.example:draft-peer", auth: "chap", "chap-user": "draft-user", "secret-ref": "draft-secret", "target-user": "", "target-secret-ref": "" };
}

// Complete submitted policy, not a mocked response: used by the real browser
// against the actual Go preview handler. Read-only shares still expose a LUN.
export function iscsiExposurePolicyFixture() {
  const c = iscsiPolicyFixture();
  c.file_services.shares.users = [{ id: "reader", name: "reader" }];
  c.file_services.shares.shares = [{ id: "share", name: "Private share name", volume_id: "bulk", relative_path: ".", grants: [{ user_id: "reader", access: "ro" }] }];
  c.file_services.nfs.exports = [{ id: "aaaaaaaa-1111-2222-3333-444444444444", volume_id: "bulk", relative_path: "luns",
    clients: [{ network: "198.51.100.1/32", access: "ro", squash: "all", anonymous_uid: 65534, anonymous_gid: 65534, security: "sys" }] }];
  return c;
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
  assert.match(text(h.elements["iscsi-result"]), /No lexical overlap.*not proof of safe use/);
  const overlap = iscsiPreviewFixture(); overlap.smb_definitions = 128; overlap.nfs_definitions = 128;
  overlap.backings[0].smb_path_overlap_count = 128; overlap.backings[0].nfs_path_overlap_count = 128;
  h.context.renderISCSIPreview(overlap);
  assert.match(text(h.elements["iscsi-result"]), /128 SMB share\(s\), 128 NFS export\(s\)/);
  assert.match(text(h.elements["iscsi-result"]), /Review potential backing-file exposure/);
  assert.match(text(h.elements["iscsi-result"]), /including read-only shares and disabled targets/);
  assert.match(text(h.elements["iscsi-result"]), /Zero configured overlaps does not prove isolation/);
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
    p => { p.schema_version = 1; }, p => { p.schema_version = 3; },
    ...["smb_path_overlap_count", "nfs_path_overlap_count"].flatMap(key => [
      p => { delete p.backings[0][key]; }, p => { p.backings[0][key] = -1; },
      p => { p.backings[0][key] = 1; }, p => { p.backings[0][key] = 129; },
      p => { p.backings[0][key] = "0"; }, p => { p.backings[0][key] = 0.5; },
      p => { p.backings[0][key] = null; }, p => { p.backings[0][key] = NaN; },
    ]),
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
  await testISCSIDraft(createHarness, jsonResponse, common);
  process.stdout.write("iSCSI panel controls passed: manual-only=true whole-policy=true exact-decimals=true bounds=true deadlines=4 private-clear=true activation=false.\n");
}

async function testISCSIDraft(createHarness, jsonResponse, common) {
  const path = "/api/v1/iscsi/preview", original = iscsiPolicyFixture(), source = JSON.stringify(original);
  const fill = h => {
    h.elements["iscsi-document"].value = source;
    for (const [name, value] of Object.entries(iscsiDraftFieldsFixture())) h.elements[`iscsi-draft-${name}`].value = value;
  };
  const reply = (route, options) => route === path ? jsonResponse(iscsiPreviewForPolicy(JSON.parse(options.body))) : common(route);
  const h = await createHarness(reply); fill(h);
  const result = h.context.buildISCSIDraft(source, iscsiDraftFieldsFixture());
  const c = JSON.parse(result.text);
  assert.equal(c.revision, 2);
  for (const r of [c.file_services.revision, c.file_services.shares.revision, c.file_services.nfs.revision, c.file_services.nfs.volume_revision, c.iscsi.revision, c.iscsi.volume_revision]) assert.equal(r, 2);
  assert.deepEqual(c.iscsi.targets[0], original.iscsi.targets[0]); assert.deepEqual(c.iscsi.backings[0], original.iscsi.backings[0]);
  assert.deepEqual(c.file_services.shares.volumes, original.file_services.shares.volumes);
  assert.equal(c.iscsi.targets[1].state, "disabled"); assert.equal(c.iscsi.targets[1].luns[0].number, 0);
  const linkedBase = iscsiExposurePolicyFixture();
  const linked = JSON.parse(h.context.buildISCSIDraft(JSON.stringify(linkedBase), iscsiDraftFieldsFixture()).text);
  for (const key of ["volumes","users","shares"]) assert.deepEqual(linked.file_services.shares[key],linkedBase.file_services.shares[key]);
  assert.deepEqual(linked.file_services.nfs.exports,linkedBase.file_services.nfs.exports);
  const extendFields = { ...iscsiDraftFieldsFixture(), mode:"existing-target", "target-id":result.targetID, path:"luns/extra.img" };
  const extended = JSON.parse(h.context.buildISCSIDraft(result.text,extendFields).text);
  assert.equal(extended.revision,3); assert.equal(extended.iscsi.targets.length,2);
  assert.equal(extended.iscsi.backings.length,3);
  assert.deepEqual(extended.iscsi.targets[0],c.iscsi.targets[0]);
  assert.equal(extended.iscsi.targets[1].state,"disabled");
  assert.equal(extended.iscsi.targets[1].luns.length,2);
  assert.deepEqual(extended.iscsi.targets[1].luns[0],c.iscsi.targets[1].luns[0]);
  assert.equal(extended.iscsi.targets[1].luns[1].number,1);
  assert.equal(extended.iscsi.targets[1].initiators.length,1);
  assert.deepEqual(extended.iscsi.targets[1].initiators[0].authentication,c.iscsi.targets[1].initiators[0].authentication);
  assert.deepEqual(extended.iscsi.targets[1].initiators[0].grants[0],c.iscsi.targets[1].initiators[0].grants[0]);
  assert.equal(extended.iscsi.targets[1].initiators[0].grants.length,2);
  const newPeer = JSON.parse(h.context.buildISCSIDraft(result.text,{ ...extendFields, initiator:"iqn.2026-01.org.example:another-peer", "chap-user":"another", "secret-ref":"another-secret", access:"rw" }).text);
  assert.deepEqual(newPeer.iscsi.targets[1].initiators[0],c.iscsi.targets[1].initiators[0]);
  assert.equal(newPeer.iscsi.targets[1].initiators[1].grants.length,1);
  assert.equal(newPeer.iscsi.targets[1].initiators[1].grants[0].access,"rw");
  for (const change of [{"target-id":"missing"}, {name:"iqn.2026-01.org.example:wrong"}, {"secret-ref":"replacement"}, {"chap-user":"replacement"}, {mode:"unknown"}]) {
    assert.throws(()=>h.context.buildISCSIDraft(result.text,{...extendFields,...change}),/Invalid guided/);
  }
  assert.throws(()=>h.context.buildISCSIDraft(source,{...extendFields,"target-id":"target",name:original.iscsi.targets[0].name}),/Invalid guided/);
  assert.throws(()=>h.context.buildISCSIDraft(source,{...iscsiDraftFieldsFixture(),"target-id":"ignored"}),/Invalid guided/);
  const second = JSON.parse(h.context.buildISCSIDraft(result.text, { ...iscsiDraftFieldsFixture(), name: "iqn.2026-01.org.example:second", path: "luns/second.img", "secret-ref": "second-secret" }).text);
  assert.notEqual(second.iscsi.targets[1].id, second.iscsi.targets[2].id);
  assert.notEqual(second.iscsi.targets[1].luns[0].id, second.iscsi.targets[2].luns[0].id);
  assert.equal(JSON.stringify(original), source, "caller data unchanged");
  await h.context.submitISCSIPreview(undefined, true);
  const posts = h.requests.filter(r => r.path === path);
  assert.equal(posts.length, 2); assert.equal(posts[0].options.body, source); assert.equal(posts[1].options.body, result.text);
  assert.ok(posts.every(r => r.options.method === "POST" && r.options.headers["X-PhantoWD-CSRF"] === "a".repeat(43)));
  assert.equal(h.elements["iscsi-document"].value, result.text); assert.match(h.elements["iscsi-status"].textContent, /draft only/);
  assert.match(text(h.elements["iscsi-result"]), /desired disabled/); assert.doesNotMatch(text(h.elements["iscsi-result"]), /draft-user|draft-secret/);
  assert.equal(h.elements["iscsi-draft-add"].disabled, false); assert.equal(h.elements["iscsi-draft-fields"].disabled, false);
  assert.ok(h.requests.every(r => r.options?.method !== "PUT" && r.options?.method !== "DELETE"));
  const mutual = { ...iscsiDraftFieldsFixture(), auth: "mutual-chap", "target-user": "target-user", "target-secret-ref": "target-secret" };
  const mc = JSON.parse(h.context.buildISCSIDraft(source, mutual).text);
  assert.equal(mc.iscsi.targets[1].initiators[0].authentication.target_secret_ref, "target-secret");
  const mutualDraft = h.context.buildISCSIDraft(source,mutual);
  const mutualExtended = JSON.parse(h.context.buildISCSIDraft(mutualDraft.text,{...mutual,mode:"existing-target","target-id":mutualDraft.targetID,path:"luns/mutual-extra.img"}).text);
  assert.deepEqual(mutualExtended.iscsi.targets[1].initiators[0].authentication,mc.iscsi.targets[1].initiators[0].authentication);
  assert.equal(mutualExtended.iscsi.targets[1].initiators[0].grants.length,2);
  for (const fields of [
    { capacity:"9007199254740992" }, { capacity:"8193" }, { capacity:"1e4" }, { capacity:"08192" }, { capacity:"0" },
    { "block-size":"1024" }, { access:"none" }, { auth:"none" }, { volume:"missing" }, { path:"../escape.img" }, { path:"/absolute" }, { path:"a\\b" }, { path:"a//b" },
    { "secret-ref":"secret value" }, { "chap-user":"a\nPRIVATE" }, { "target-user":"unused" },
  ]) assert.throws(() => h.context.buildISCSIDraft(source, { ...iscsiDraftFieldsFixture(), ...fields }), /Invalid guided/);
  assert.throws(() => h.context.buildISCSIDraft(source.replace('"revision":1', '"revision":9007199254740991'), iscsiDraftFieldsFixture()), /Invalid guided/);
  assert.throws(() => h.context.buildISCSIDraft(source.replace('"capacity_bytes":4096', '"capacity_bytes":9007199254740993'), iscsiDraftFieldsFixture()), /Invalid guided/);
  assert.throws(() => h.context.buildISCSIDraft(source, { ...mutual, "target-secret-ref":"draft-secret" }), /Invalid guided/);
  // Original strict input must be accepted first; never normalize duplicate
  // keys/invalid schemas into a candidate that the server might accept.
  for (const phase of ["base", "candidate", "projection", "projection-lun"]) {
    let n = 0;
    const refused = await createHarness((route, options) => {
      if (route !== path) return common(route);
      n++;
      if (phase === "base" || phase === "candidate" && n === 2) return jsonResponse({ error:"PRIVATE" },422);
      const value = phase === "projection" && n === 2 ? iscsiPreviewFixture() : iscsiPreviewForPolicy(JSON.parse(options.body));
      if (phase === "projection-lun" && n === 2) {
        value.targets[1].luns[0].id = "substituted-lun";
        value.targets[1].initiators[0].grants[0].lun_id = "substituted-lun";
      }
      return jsonResponse(value);
    });
    fill(refused);
    if (phase === "base") refused.elements["iscsi-document"].value = source.replace('"revision":1', '"revision":1,"revision":1');
    const saved = refused.elements["iscsi-document"].value;
    await refused.context.submitISCSIPreview(undefined,true);
    assert.equal(refused.elements["iscsi-document"].value,saved); assert.equal(refused.elements["iscsi-result"].hidden,true);
    assert.equal(n,phase === "base" ? 1 : 2); assert.doesNotMatch(refused.elements["iscsi-status"].textContent,/PRIVATE/);
  }
  // The second validation shares the ORIGINAL single10s deadline. Expired or
  // retired candidate responses cannot replace original text or a newer view.
  for (const bodyStall of [false,true]) for (const retirement of ["timeout","edit","logout"]) {
    const timers = new Map(); let id = 0, release, calls = 0, entered = false;
    const gate = new Promise(resolve => { release = resolve; });
    const b = await createHarness(async (route,options) => {
      if (route !== path) return common(route);
      if (++calls === 2) {
        entered = true;
        if (bodyStall) return { ok:true,status:200,body:{getReader:()=>({read:async()=>{await gate;return {done:false,value:new TextEncoder().encode(JSON.stringify(iscsiPreviewFixture()))};},cancel:async()=>{},releaseLock(){}})} };
        await gate; return jsonResponse({},401);
      }
      return jsonResponse(iscsiPreviewForPolicy(JSON.parse(options.body)));
    }, { setTimeout(callback,delay) { const key = ++id; timers.set(key,{callback,delay}); return key; },clearTimeout(key) { timers.delete(key); } });
    fill(b);
    const work = b.context.submitISCSIPreview(undefined,true); await turn(); assert.equal(entered,true);
    assert.equal(b.elements["iscsi-draft-add"].disabled,true); assert.equal(b.elements["iscsi-draft-fields"].disabled,true);
    const before = b.requests.length; await b.context.submitISCSIPreview(undefined,true); assert.equal(b.requests.length,before);
    if (retirement === "timeout") { assert.equal(timers.size,1); const timer = [...timers.values()][0]; assert.equal(timer.delay,10000); timer.callback(); }
    else if (retirement === "edit") b.elements["iscsi-draft-name"].listeners.get("input")();
    else b.context.showAuthUnavailable();
    await work;
    assert.equal(b.elements["iscsi-document"].value,retirement === "logout" ? "" : source);
    assert.equal(b.elements["iscsi-result"].hidden,true);
    if (retirement === "logout") for (const name of ["name","path","initiator","chap-user","secret-ref","target-user","target-secret-ref"]) assert.equal(b.elements[`iscsi-draft-${name}`].value,"");
    b.elements["dashboard-content"].hidden = false; fill(b);
    await b.context.submitISCSIPreview(); assert.equal(b.elements["iscsi-result"].hidden,false);
    release(); await turn(); await turn();
    assert.equal(b.elements["iscsi-result"].hidden,false); assert.equal(b.elements["iscsi-document"].value,source);
    assert.equal(b.elements["dashboard-content"].hidden,false);
  }
  h.context.clearISCSIPreview();
  for (const name of ["name","volume","path","capacity","initiator","chap-user","secret-ref","target-user","target-secret-ref"]) assert.equal(h.elements[`iscsi-draft-${name}`].value,"");
  process.stdout.write("iSCSI guided draft controls passed: disabled-first=true original-and-candidate-validation=true safe-integers=true preserved-definitions=true extend-lun=true credentials-preserved=true projection-bound=true shared-deadline=true retirement=6 writes=false.\n");
}
