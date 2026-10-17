// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

import { createHash } from "node:crypto";

// The installed Edge155 emitted this exact inline SVG during real text input.
// It is a local image load, not a network request. No generic data/blob/about
// exception: changed bytes, methods or resource types require fresh review.
const inlineSVG = { length: 510, sha256: "4b52bc3e8d7825a3fca0aa8a1d541a413164bbb984eaf437373cb99e123dd799" };
const fixturePostPaths = new Set([
  ...["setup", "login", "logout", "logout-all", "password"].map(action => `/api/v1/auth/${action}`),
  "/api/v1/iscsi/preview", // Caller-supplied read-only preview, never save/apply.
  "/api/v1/network/preview", // Desired document only, never network observation/apply.
]);

export function classifyPageResource(request, origin, allowAuthMutations = false, allowPolicyFixture = false) {
  const refused = () => { throw new Error("unexpected browser page resource"); };
  if (!request || typeof request.url !== "string" || request.url.length > 8192 || typeof origin !== "string") refused();
  let base, url;
  try { base = new URL(origin); url = new URL(request.url); } catch { refused(); }
  if (base.protocol !== "http:" || base.hostname !== "127.0.0.1" || !base.port || base.origin !== origin) refused();
  if (url.protocol === "data:") {
    if (request.method === "GET" && request.resourceType === "Image" && request.url.length === inlineSVG.length &&
        request.url.startsWith("data:image/svg+xml;base64,") && createHash("sha256").update(request.url).digest("hex") === inlineSVG.sha256) {
      return "local-inline-image";
    }
    refused();
  }
  if (url.protocol !== "http:" || url.origin !== origin || url.username || url.password) refused();
  const policyRequest = allowAuthMutations === true && allowPolicyFixture === true && !url.search &&
    ((request.method === "PUT" && url.pathname === "/api/v1/file-services/configuration") ||
     (request.method === "POST" && ["/api/v1/file-services/preview", "/api/v1/file-services/restore-preview"].includes(url.pathname)));
  if (request.method !== "GET" && !policyRequest && !(allowAuthMutations === true && request.method === "POST" && !url.search && fixturePostPaths.has(url.pathname))) refused();
  return "same-origin-network";
}
