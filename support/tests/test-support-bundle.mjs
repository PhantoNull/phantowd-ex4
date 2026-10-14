// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createContext, Script } from "node:vm";

const source = await readFile(new URL("../../src/phantowd-api/ui/support-bundle.js", import.meta.url), "utf8");
const context = createContext({ TextEncoder, Date });
new Script(source).runInContext(context);
const factory = new Script("PhantoWDSupportBundle").runInContext(context);
const received = Date.parse("2026-01-01T00:00:00Z");

export function supportFixture() {
  const privateValue = "PRIVATE-SENTINEL-42";
  return {
    system: { schema_version: 1, target: "qemu-armv5", architecture: "arm", goarm: "5", kernel: `6.18.55-${privateValue}`,
      flashable: false, hardware_validated: false, uptime_seconds: 100.5,
      memory: { total_bytes: 512 * 1024 ** 2, available_bytes: 128 * 1024 ** 2 }, effective_uid: 1234,
      hostname: privateValue, token: privateValue },
    storage: { schema_version: 2, scope: "kernel-sysfs-only", inventory_read_only: true,
      block_devices_opened: false, content_read: false, mutations_performed: false, stable_identity_available: false,
      device_count: 2, observations: [
        { name: privateValue, kind: "block", read_only: false, removable: true, serial_status: "ambiguous", wwn_status: "present", serial: privateValue, wwn: privateValue },
        { name: privateValue, kind: "partition", read_only: true, removable: false, parent_name: privateValue, uuid: privateValue },
      ], limitations: [privateValue] },
    arrays: { schema_version: 1, status: "partial", read_only: true, block_devices_opened: false,
      disk_content_read: false, mutations_performed: false, array_count: 2,
      arrays: [{ name: privateValue, health: "healthy", members: [{ name: privateValue }] }, { name: privateValue, health: "degraded", error: privateValue }], limitations: [privateValue] },
    mounts: { schema_version: 1, scope: "current-process-mount-namespace", read_only: true,
      filesystem_contents_read: false, mount_operations_performed: false, mount_count: 2,
      mounts: [{ mount_point: privateValue, filesystem: "ext4", read_only: false, options: privateValue },
        { mount_point: privateValue, filesystem: privateValue, read_only: true }], limitations: [privateValue] },
    configuration: { user: privateValue, address: "192.0.2.9", key: privateValue }, logs: [privateValue],
  };
}

const report = factory.create(supportFixture(), received);
const text = report.serialize(received + 12000);
const parsed = JSON.parse(text);
assert.equal(parsed.format, "phantowd-sanitized-support");
assert.equal(parsed.schema_version, 1);
assert.equal(parsed.atomic_snapshot, false);
assert.equal(parsed.snapshot_age_seconds, 12);
assert.equal(parsed.observations.system.kernel_base, "6.18.55");
assert.equal(parsed.observations.system.uptime_seconds, 100);
assert.equal(parsed.observations.storage.block_count, 1);
assert.equal(parsed.observations.storage.partition_count, 1);
assert.equal(parsed.observations.storage.serial_status.ambiguous, 1);
assert.equal(parsed.observations.arrays.status, "partial");
assert.equal(parsed.observations.arrays.health.degraded, 1);
assert.equal(parsed.observations.mounts.filesystems.ext4, 1);
assert.equal(parsed.observations.mounts.filesystems.other, 1);
assert.ok(!text.includes("PRIVATE-SENTINEL") && !text.includes("192.0.2.9"));
for (const key of ["effective_uid", "hostname", "token", "serial", "wwn", "uuid", "name", "parent_name", "members", "mount_point", "options", "configuration", "logs"]) {
  assert.ok(!text.includes(`"${key}":`), `private field ${key} leaked`);
}
assert.ok(new TextEncoder().encode(text).byteLength <= 4096);

// Factory projections have no references to mutable source objects.
const mutable = supportFixture();
const retained = factory.create(mutable, received);
mutable.system.memory.available_bytes = 0;
mutable.arrays.arrays[1].health = "healthy";
mutable.mounts.mounts[0].filesystem = "cifs";
mutable.system.toJSON = () => ({ secret: "PRIVATE-SENTINEL" });
assert.equal(retained.serialize(received + 12000), text);
const absent = JSON.parse(factory.create({}, received).serialize(received));
for (const domain of ["system", "storage", "arrays", "mounts"]) assert.equal(absent.observations[domain].status, "unavailable");
const backwards = JSON.parse(report.serialize(received - 1000));
assert.equal(backwards.age_status, "clock-regressed");
assert.equal(backwards.snapshot_age_seconds, null);
for (const badClock of [NaN, Infinity, -1, 0.5, 8640000000000001, "2026-01-01", null]) {
  assert.throws(() => factory.create({}, badClock));
  assert.throws(() => report.serialize(badClock));
}

const mutations = [
  ["system", (f) => { f.schema_version = 2; }],
  ["system", (f) => { f.memory.available_bytes = f.memory.total_bytes + 1; }],
  ["system", (f) => { f.memory.total_bytes = Number.MAX_SAFE_INTEGER + 1; }],
  ["system", (f) => { f.uptime_seconds = NaN; }],
  ["system", (f) => { f.flashable = "false"; }],
  ["storage", (f) => { f.schema_version = 1; }],
  ["storage", (f) => { f.device_count++; }],
  ["storage", (f) => { f.block_devices_opened = true; }],
  ["storage", (f) => { f.stable_identity_available = true; }],
  ["storage", (f) => { f.observations[0].kind = "__proto__"; }],
  ["storage", (f) => { f.observations[0].serial_status = "__proto__"; }],
  ["storage", (f) => { f.observations[0].read_only = null; }],
  ["arrays", (f) => { f.array_count++; }],
  ["arrays", (f) => { f.status = "__proto__"; }],
  ["arrays", (f) => { f.status = "unavailable"; }],
  ["arrays", (f) => { f.arrays[0].health = "__proto__"; }],
  ["arrays", (f) => { f.disk_content_read = true; }],
  ["mounts", (f) => { f.scope = "unknown"; }],
  ["mounts", (f) => { f.mount_count++; }],
  ["mounts", (f) => { f.mount_operations_performed = true; }],
  ["mounts", (f) => { f.mounts[0].read_only = 1; }],
];
for (const [domain, mutate] of mutations) {
  const input = supportFixture();
  mutate(input[domain]);
  const result = JSON.parse(factory.create(input, received).serialize(received));
  assert.deepEqual(result.observations[domain], { status: "invalid" }, `invalid ${domain} exported partial fields`);
  for (const other of ["system", "storage", "arrays", "mounts"].filter((key) => key !== domain)) {
    assert.ok(["available", "partial"].includes(result.observations[other].status), "invalid domain erased independent observations");
  }
}
for (const [domain, list, count, max] of [["storage", "observations", "device_count", 32], ["arrays", "arrays", "array_count", 16], ["mounts", "mounts", "mount_count", 128]]) {
  const input = supportFixture();
  input[domain][list] = Array.from({ length: max }, () => ({ ...input[domain][list][0] }));
  input[domain][count] = max;
  input[domain].ignored = "PRIVATE-SENTINEL".repeat(100000);
  const atLimit = factory.create(input, received).serialize(received);
  assert.ok(new TextEncoder().encode(atLimit).byteLength <= 4096 && !atLimit.includes("PRIVATE-SENTINEL"));
  input[domain][list].push({ ...input[domain][list][0] });
  input[domain][count]++;
  assert.deepEqual(JSON.parse(factory.create(input, received).serialize(received)).observations[domain], { status: "invalid" });
}
for (const status of ["unavailable", "unsupported"]) {
  const input = supportFixture();
  input.arrays.status = status;
  input.arrays.arrays = [];
  input.arrays.array_count = 0;
  assert.equal(JSON.parse(factory.create(input, received).serialize(received)).observations.arrays.status, status);
}
for (const kernel of ["192.0.2.9", "PRIVATE-SENTINEL", "6.18.55\nPRIVATE-SENTINEL", "6".repeat(129)]) {
  const input = supportFixture();
  input.system.kernel = kernel;
  assert.equal(JSON.parse(factory.create(input, received).serialize(received)).observations.system.kernel_base, "unknown");
}
process.stdout.write("Sanitized support report projection, privacy, bounds and clock controls passed.\n");
