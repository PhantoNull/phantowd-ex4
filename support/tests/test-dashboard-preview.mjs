// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Actual loopback HTTP asset checks, not browser/rendering qualification.
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createPreviewServer } from "../dashboard-preview.mjs";

const server = createPreviewServer();
try {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(origin);
  assert.equal(page.status, 200);
  const markup = await page.text();
  assert.equal(markup, await readFile(new URL("../../src/phantowd-api/ui/index.html", import.meta.url), "utf8"));
  const paths = new Set([...markup.matchAll(/\b(?:src|href)="(\/assets\/[^"?#]+)"/g)].map(m => m[1]));
  assert.ok(paths.has("/assets/iscsi-preview.js"), "exercise the actual iSCSI dependency");
  for (const path of paths) {
    const asset = await fetch(origin + path);
    assert.equal(asset.status, 200, `page dependency ${path}`);
    assert.deepEqual(Buffer.from(await asset.arrayBuffer()),
      await readFile(new URL(`../../src/phantowd-api/ui/${path.slice("/assets/".length)}`, import.meta.url)), path);
    const mime = path.endsWith(".js") ? "text/javascript" : path.endsWith(".css") ? "text/css" : "image/svg+xml";
    assert.equal(asset.headers.get("content-type").split(";")[0], mime, path);
    assert.equal(asset.headers.get("cache-control"), "no-store");
    assert.equal(asset.headers.get("x-content-type-options"), "nosniff");
  }
  for (const [path, method, status] of [
    ["/assets/iscsi-preview.js", "POST", 405],
    ["/assets/iscsi-preview.js?extra=1", "GET", 400],
    ["/assets/not-listed.js", "GET", 404],
    ["/support/dashboard-preview.mjs", "GET", 404],
  ]) {
    const refused = await fetch(origin + path, { method });
    assert.equal(refused.status, status, `${method} ${path}`);
    assert.match(refused.headers.get("content-type"), /^application\/json/);
    await refused.arrayBuffer();
  }
  console.log(`Dashboard preview: ${paths.size} HTML dependencies served with exact bytes and MIME`);
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
}
