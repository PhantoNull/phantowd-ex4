// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Real browser forms and HTTP handlers, explicitly memory-only desired state.
// No service activation, disk collector or persistent appliance state.
import assert from "node:assert/strict";

export async function exerciseServicePolicy({ evaluate, clickVisible, replaceInput, key, until, browser, inspectLayout }) {
  assert.equal(typeof inspectLayout, "function", "real policy layout observer required");
  const input = async (id, value) => {
    await clickVisible(id);
    await replaceInput(id, value);
  };
  const choose = async (id, value) => {
    const index = await evaluate(`Array.from(document.getElementById(${JSON.stringify(id)}).options).findIndex(o => o.value === ${JSON.stringify(value)})`);
    assert.ok(Number.isSafeInteger(index) && index >= 0 && index < 260, "choice unavailable");
    await clickVisible(id);
    await key("Home", "Home", 36);
    for (let i = 0; i < index; i++) await key("ArrowDown", "ArrowDown", 40);
    await key("Enter", "Enter", 13);
    await key("Tab", "Tab", 9);
    assert.equal(await evaluate(`document.getElementById(${JSON.stringify(id)}).value`), value);
  };
  const load = async (revision) => {
    await clickVisible("service-load");
    await until(() => evaluate(`!document.getElementById('service-load').disabled && document.getElementById('service-summary').textContent.includes(${JSON.stringify(revision === 0 ? "no configuration initialized" : `Saved revision ${revision}:`)})`), browser, "saved desired policy load");
  };
  const saved = () => evaluate("JSON.parse(document.getElementById('service-document').textContent)");
  const previewAndSave = async (button, revision, layoutPhase = null) => {
    await clickVisible(button);
    await until(() => evaluate("!document.getElementById('service-review').hidden && !document.getElementById('service-save').disabled"), browser, "complete policy review");
    assert.match(await evaluate("document.getElementById('service-change').textContent"), /No service activation/);
    if (layoutPhase !== null) await inspectLayout(layoutPhase);
    await clickVisible("service-save");
    await until(() => evaluate(`!document.getElementById('service-load').disabled && document.getElementById('service-summary').textContent.includes('Saved revision ${revision}:')`), browser, "explicit desired policy save");
    await load(revision);
    return saved();
  };
  await load(0);
  const fixture = { uuid: "11111111-2222-4333-8444-555555555555", name: "Browser" + "L".repeat(73),
    path: "books/" + "a".repeat(252) + "/" + "b".repeat(253), user: "reader" + "a".repeat(26) };
  // Start with NFS alone through visible controls: no hidden prerequisite SMB
  // share or user reference. The original combined-add/edit/remove path follows.
  await choose("service-action", "nfs-add");
  await input("policy-uuid", fixture.uuid);
  await input("policy-path", "standalone");
  await input("policy-export-id", "bbbbbbbb-7777-4888-8999-aaaaaaaaaaaa");
  await input("policy-network", "203.0.113.8/32");
  const standalone = await previewAndSave("service-edit-preview", 1);
  assert.equal(standalone.shares.shares.length, 0);
  assert.equal(standalone.shares.users.length, 0);
  assert.equal(standalone.shares.volumes.length, 1);
  assert.equal(standalone.nfs.exports.length, 1);
  assert.equal(standalone.nfs.exports[0].relative_path, "standalone");
  assert.deepEqual(standalone.nfs.exports[0].clients, [{ network: "203.0.113.8/32", access: "ro", squash: "all",
    anonymous_uid: 65534, anonymous_gid: 65534, security: "sys" }]);
  assert.equal(standalone.nfs.exports[0].volume_id, standalone.shares.volumes[0].id);
  for (const [name, value] of Object.entries(fixture)) {
    await input(`policy-${name}`, value);
  }
  await choose("policy-nfs-enabled", "on");
  await input("policy-export-id", "66666666-7777-4888-8999-aaaaaaaaaaaa");
  await input("policy-network", "198.51.100.7/32");
  await inspectLayout("draft");
  const first = await previewAndSave("service-prepare", 2, "review-1");
  assert.equal(first.shares.shares.length, 1);
  assert.equal(first.nfs.exports.length, 2);
  assert.deepEqual(first.shares.volumes, standalone.shares.volumes, "same filesystem addition duplicated volume reference");
  assert.deepEqual(first.nfs.exports[0], standalone.nfs.exports[0], "combined addition changed unrelated NFS");
  assert.equal(first.nfs.exports[1].relative_path, fixture.path);
  assert.equal(first.nfs.exports[1].clients[0].network, "198.51.100.7/32");
  assert.equal(first.shares.shares[0].grants[0].access, "ro");
  assert.equal(first.shares.shares[0].name, fixture.name, "long share name was not preserved");
  assert.equal(first.shares.shares[0].relative_path, fixture.path, "long relative path was not preserved");
  assert.equal(first.shares.users[0].name, fixture.user, "long user reference was not preserved");
  const smb = first.shares.shares[0];
  await choose("service-target", `smb:${smb.id}`);
  await choose("service-member", smb.grants[0].user_id);
  await choose("service-action", "smb-grant-upsert");
  await choose("policy-smb-access", "rw");
  const second = await previewAndSave("service-edit-preview", 3, "review-2");
  assert.equal(second.shares.shares[0].grants[0].access, "rw");
  assert.deepEqual(second.nfs.exports, first.nfs.exports, "SMB edit changed NFS");
  assert.deepEqual(second.shares.volumes, first.shares.volumes);
  await choose("service-target", `nfs:${first.nfs.exports[1].id}`);
  await choose("service-action", "nfs-remove");
  const third = await previewAndSave("service-edit-preview", 4, "review-3");
  assert.deepEqual(third.nfs.exports, standalone.nfs.exports, "selected removal changed unrelated NFS");
  assert.deepEqual(third.shares, { ...second.shares, revision: 4 }, "NFS removal changed SMB");
  assert.equal(third.revision, 4);
  return { revisions: 4, independent_nfs_first: true, combined_addition_preserves_nfs: true, smb_grant_edit: true,
    nfs_removal_preserves_smb: true, nfs_removal_preserves_other_export: true, persistence_qualified: false, activation_qualified: false };
}
