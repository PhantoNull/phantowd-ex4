// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

// An allowlisted browser report, not a device attestation or appliance backup.
// Never retain the source snapshot, serialize unknown fields, or perform I/O.
const PhantoWDSupportBundle = (() => {
  const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const integer = (value) => Number.isSafeInteger(value) && value >= 0;
  const unavailable = (value) => ({ status: value == null ? "unavailable" : "invalid" });
  const pick = (value, choices, fallback = "other") => choices.includes(value) ? value : fallback;
  const clock = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000000;
  const healthStates = ["healthy", "degraded", "syncing", "paused", "inactive", "unknown"];
  const identityStates = ["unavailable", "present", "invalid", "ambiguous", "unreadable"];
  const histogram = (keys) => Object.fromEntries(keys.map((key) => [key, 0]));

  function system(value) {
    if (!record(value) || value.schema_version !== 1 || !record(value.memory) ||
        !integer(value.memory.total_bytes) || value.memory.total_bytes === 0 ||
        !integer(value.memory.available_bytes) || value.memory.available_bytes > value.memory.total_bytes ||
        !Number.isFinite(value.uptime_seconds) || value.uptime_seconds < 0 || value.uptime_seconds > Number.MAX_SAFE_INTEGER ||
        typeof value.flashable !== "boolean" || typeof value.hardware_validated !== "boolean") return unavailable(value);
    // A numeric base only: local build labels can contain private names.
    const kernel = typeof value.kernel === "string" && value.kernel.length <= 128 ?
      value.kernel.match(/^([0-9]{1,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?)(?:[-+_][A-Za-z0-9._+-]{1,110})?$/)?.[1] : null;
    return {
      status: "available", target: pick(value.target, ["qemu-armv5", "ui-preview-fixture"]),
      architecture: pick(value.architecture, ["arm", "arm64", "amd64", "386"]),
      goarm: pick(value.goarm, ["5", "5,softfloat", "6", "7"], "unspecified"),
      kernel_base: kernel || "unknown", flashable: value.flashable,
      hardware_validated: value.hardware_validated, uptime_seconds: Math.floor(value.uptime_seconds),
      memory: { total_bytes: value.memory.total_bytes, available_bytes: value.memory.available_bytes },
    };
  }

  function storage(value) {
    if (!record(value) || value.schema_version !== 2 || value.scope !== "kernel-sysfs-only" ||
        value.inventory_read_only !== true || value.block_devices_opened !== false || value.content_read !== false ||
        value.mutations_performed !== false || value.stable_identity_available !== false ||
        !Array.isArray(value.observations) || value.observations.length > 32 || value.device_count !== value.observations.length) return unavailable(value);
    const summary = { status: "available", device_count: value.device_count, block_count: 0, partition_count: 0,
      read_only_count: 0, removable_count: 0, serial_status: histogram(identityStates), wwn_status: histogram(identityStates) };
    for (const item of value.observations) {
      if (!record(item) || !["block", "partition"].includes(item.kind) ||
          typeof item.read_only !== "boolean" || typeof item.removable !== "boolean") return unavailable(value);
      summary[item.kind === "block" ? "block_count" : "partition_count"]++;
      if (item.read_only) summary.read_only_count++;
      if (item.removable) summary.removable_count++;
      if (item.kind === "block") {
        if (!identityStates.includes(item.serial_status) || !identityStates.includes(item.wwn_status)) return unavailable(value);
        summary.serial_status[item.serial_status]++;
        summary.wwn_status[item.wwn_status]++;
      }
    }
    return summary;
  }

  function arrays(value) {
    if (!record(value) || value.schema_version !== 1 || value.read_only !== true ||
        value.block_devices_opened !== false || value.disk_content_read !== false || value.mutations_performed !== false ||
        !["available", "partial", "unavailable", "unsupported"].includes(value.status) ||
        !Array.isArray(value.arrays) || value.arrays.length > 16 || value.array_count !== value.arrays.length ||
        (["unavailable", "unsupported"].includes(value.status) && value.arrays.length !== 0)) return unavailable(value);
    const summary = { status: value.status, observed_array_count: value.array_count, health: histogram(healthStates) };
    for (const item of value.arrays) {
      if (!record(item) || !healthStates.includes(item.health)) return unavailable(value);
      summary.health[item.health]++;
    }
    return summary;
  }

  function mounts(value) {
    if (!record(value) || value.schema_version !== 1 || value.scope !== "current-process-mount-namespace" ||
        value.read_only !== true || value.filesystem_contents_read !== false || value.mount_operations_performed !== false ||
        !Array.isArray(value.mounts) || value.mounts.length > 128 || value.mount_count !== value.mounts.length) return unavailable(value);
    const filesystemTypes = ["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "tmpfs", "devtmpfs", "proc", "sysfs", "squashfs", "ubifs", "nfs", "nfs4", "cifs", "overlay", "other"];
    const summary = { status: "available", observed_mount_count: value.mount_count, read_only_count: 0, filesystems: histogram(filesystemTypes) };
    for (const item of value.mounts) {
      if (!record(item) || typeof item.read_only !== "boolean" || typeof item.filesystem !== "string") return unavailable(value);
      if (item.read_only) summary.read_only_count++;
      summary.filesystems[pick(item.filesystem, filesystemTypes)]++;
    }
    return summary;
  }

  function create(loaded, receivedAt) {
    if (!record(loaded) || !clock(receivedAt)) throw new Error("invalid support snapshot");
    // Only these new primitive-valued projections survive in the closure.
    const observations = { system: system(loaded.system), storage: storage(loaded.storage), arrays: arrays(loaded.arrays), mounts: mounts(loaded.mounts) };
    loaded = null;
    return Object.freeze({ serialize(now) {
      if (!clock(now)) throw new Error("invalid support export clock");
      const text = JSON.stringify({
        format: "phantowd-sanitized-support", schema_version: 1,
        scope: "browser-loaded-read-only-snapshot", atomic_snapshot: false,
        received_at: new Date(receivedAt).toISOString(), exported_at: new Date(now).toISOString(),
        age_status: now < receivedAt ? "clock-regressed" : "elapsed-browser-clock",
        snapshot_age_seconds: now < receivedAt ? null : Math.floor((now - receivedAt) / 1000),
        observations,
        limitations: ["browser-created report, not trusted device attestation", "sections are separate observations, not an atomic snapshot",
          "no SMART, filesystem integrity, backup, effective-access or migration qualification", "export performs no new API request or device operation"],
      }, null, 2) + "\n";
      if (new TextEncoder().encode(text).byteLength > 4096) throw new Error("support report exceeds bound");
      return text;
    } });
  }

  return Object.freeze({ create });
})();
