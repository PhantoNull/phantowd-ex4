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
  const previewAndSave = async (button, revision) => {
    await clickVisible(button);
    await until(() => evaluate("!document.getElementById('service-review').hidden && !document.getElementById('service-save').disabled"), browser, "complete policy review");
    assert.match(await evaluate("document.getElementById('service-change').textContent"), /No service activation/);
    await inspectLayout(`review-${revision}`);
    await clickVisible("service-save");
    await until(() => evaluate(`!document.getElementById('service-load').disabled && document.getElementById('service-summary').textContent.includes('Saved revision ${revision}:')`), browser, "explicit desired policy save");
    await load(revision);
    return saved();
  };
  await load(0);
  const fixture = { uuid: "11111111-2222-4333-8444-555555555555", name: "Browser" + "L".repeat(73),
    path: "books/" + "a".repeat(252) + "/" + "b".repeat(253), user: "reader" + "a".repeat(26) };
  for (const [name, value] of Object.entries(fixture)) {
    await input(`policy-${name}`, value);
  }
  await choose("policy-nfs-enabled", "on");
  await input("policy-export-id", "66666666-7777-4888-8999-aaaaaaaaaaaa");
  await input("policy-network", "198.51.100.7/32");
  await inspectLayout("draft");
  const first = await previewAndSave("service-prepare", 1);
  assert.equal(first.shares.shares.length, 1);
  assert.equal(first.nfs.exports.length, 1);
  assert.equal(first.shares.shares[0].grants[0].access, "ro");
  assert.equal(first.shares.shares[0].name, fixture.name, "long share name was not preserved");
  assert.equal(first.shares.shares[0].relative_path, fixture.path, "long relative path was not preserved");
  assert.equal(first.shares.users[0].name, fixture.user, "long user reference was not preserved");
  const smb = first.shares.shares[0];
  await choose("service-target", `smb:${smb.id}`);
  await choose("service-member", smb.grants[0].user_id);
  await choose("service-action", "smb-grant-upsert");
  await choose("policy-smb-access", "rw");
  const second = await previewAndSave("service-edit-preview", 2);
  assert.equal(second.shares.shares[0].grants[0].access, "rw");
  assert.deepEqual(second.nfs.exports, first.nfs.exports, "SMB edit changed NFS");
  assert.deepEqual(second.shares.volumes, first.shares.volumes);
  await choose("service-target", `nfs:${first.nfs.exports[0].id}`);
  await choose("service-action", "nfs-remove");
  const third = await previewAndSave("service-edit-preview", 3);
  assert.equal(third.nfs.exports.length, 0);
  assert.deepEqual(third.shares, { ...second.shares, revision: 3 }, "NFS removal changed SMB");
  assert.equal(third.revision, 3);
  return { revisions: 3, smb_grant_edit: true, nfs_removal_preserves_smb: true, persistence_qualified: false, activation_qualified: false };
}
