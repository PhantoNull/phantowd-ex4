// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

// One observation of the fresh owned profile; the caller's existing bounded
// startup loop owns all polling. Never wait here or accept another endpoint.
export async function readOwnedBrowserEndpoint(file, read = readFile) {
  let text;
  try { text = await read(file, "utf8"); }
  // Windows can deny a read while Edge publishes this one startup file.
  // Permission/I/O errors and malformed contents remain fatal.
  catch (error) { if (["ENOENT", "EBUSY"].includes(error.code)) return null; throw error; }
  const match = /^([0-9]+)\r?\n(\/devtools\/browser\/[a-z0-9-]+)\r?\n?$/.exec(text);
  assert.ok(match, "unexpected owned browser endpoint");
  const port = Number(match[1]);
  assert.ok(port >= 1024 && port <= 65535, "unexpected debugging port");
  return `ws://127.0.0.1:${port}${match[2]}`;
}
