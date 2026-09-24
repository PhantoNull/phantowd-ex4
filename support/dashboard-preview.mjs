// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Host-only visual preview for the QEMU dashboard. Synthetic fixture data is
// clearly identified in the page; this server is not part of firmware images.
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const host = "127.0.0.1";
const port = Number(process.env.PHANTOWD_PREVIEW_PORT || 18081);
const uiDirectory = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "phantowd-api", "ui");
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error("PHANTOWD_PREVIEW_PORT must be an unprivileged TCP port");
}

const systemFixture = {
  schema_version: 1,
  target: "ui-preview-fixture",
  mode: "development",
  flashable: false,
  hardware_validated: false,
  observed_at: new Date().toISOString(),
  architecture: "arm",
  goarm: "5",
  kernel: "6.18.53-preview",
  uptime_seconds: 123456,
  memory: { total_bytes: 257912832, available_bytes: 120000000 },
  effective_uid: 100,
};

const storageFixture = {
  schema_version: 1,
  scope: "preview-fixture-only",
  inventory_read_only: true,
  block_devices_opened: false,
  content_read: false,
  mutations_performed: false,
  stable_identity_available: false,
  device_count: 3,
  observations: [
    { name: "sda", kind: "block", major: 8, minor: 0, size_bytes: 2000398934016, read_only: false, removable: false, serial_status: "present", wwn_status: "present" },
    { name: "sda1", kind: "partition", major: 8, minor: 1, size_bytes: 536870912, read_only: false, removable: false, partition_number: 1 },
    { name: "sdb", kind: "block", major: 8, minor: 16, size_bytes: 2000398934016, read_only: true, removable: false, serial_status: "unavailable", wwn_status: "unavailable" },
  ],
  limitations: ["synthetic preview fixture; no device was examined"],
};

const assets = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/assets/app.css", ["app.css", "text/css; charset=utf-8"]],
  ["/assets/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/assets/ghost.svg", ["ghost.svg", "image/svg+xml"]],
]);

const server = createServer(async (request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  const url = new URL(request.url || "/", `http://${host}:${port}`);
  if (request.method !== "GET") {
    response.writeHead(405, { Allow: "GET", "Content-Type": "application/json" });
    response.end('{"error":"method_not_allowed"}\n');
    return;
  }
  if (url.search !== "") {
    response.writeHead(400, { "Content-Type": "application/json" });
    response.end('{"error":"unexpected_input"}\n');
    return;
  }
  if (url.pathname === "/api/v1/auth/status") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end('{"authenticated":true,"setup_required":false}\n');
    return;
  }
  if (url.pathname === "/api/v1/system" || url.pathname === "/api/v1/storage") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify(url.pathname.endsWith("/system") ? systemFixture : storageFixture));
    return;
  }
  const asset = assets.get(url.pathname);
  if (!asset) {
    response.writeHead(404, { "Content-Type": "application/json" });
    response.end('{"error":"not_found"}\n');
    return;
  }
  if (url.pathname === "/") {
    response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  } else {
    response.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
  }
  try {
    const body = await readFile(join(uiDirectory, asset[0]));
    response.writeHead(200, { "Content-Type": asset[1] });
    response.end(body);
  } catch {
    response.writeHead(500, { "Content-Type": "application/json" });
    response.end('{"error":"preview_asset_unavailable"}\n');
  }
});

server.listen(port, host, () => {
  process.stdout.write(`Dashboard preview at http://${host}:${port}/ (synthetic data only)\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
