// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"use strict";

function setAuthError(message) {
  const error = byId("auth-error");
  error.textContent = message;
  error.hidden = false;
}

function showAuthUnavailable() {
  const moveFocus = ["dashboard-content", "logout", "auth-form"].some((id) => byId(id).contains(document.activeElement));
  retireAuthSubmission();
  retireAuthMutation();
  clearSnapshot("Administrator session unavailable. No current diagnostic snapshot is shown.");
  clearGPTObservation("Administrator session unavailable. No GPT observation is shown.");
  clearPasswordFields();
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  byId("auth-panel").hidden = false;
  byId("dashboard-content").hidden = true;
  byId("logout").hidden = true;
  byId("auth-form").hidden = true;
  byId("auth-retry").hidden = false;
  byId("auth-password").value = "";
  setText("auth-title", "Local API unavailable.");
  setText("auth-description", "Sign-in status cannot be checked right now, so diagnostic data is hidden. Retry after the local service is available.");
  setAuthError("The local API could not be reached. No current system or storage data is shown.");
  setConnectionState("API unavailable", "unavailable");
  if (moveFocus) byId("auth-title").focus({ preventScroll: true });
}

async function updateAuthView({ refresh = true, notice = "", current = () => true, signal, requireSignedOut = false } = {}) {
  if (current() && authSubmission && signal !== authSubmission.controller.signal) retireAuthSubmission();
  if (current() && authMutation && signal !== authMutation.controller.signal) retireAuthMutation();
  const status = await fetchJSON("/api/v1/auth/status", { signal });
  if (!current()) return;
  if (requireSignedOut && status?.authenticated !== false) throw new Error("Session termination unconfirmed");
  const authPanel = byId("auth-panel");
  const dashboard = byId("dashboard-content");
  const logout = byId("logout");
  const form = byId("auth-form");
  const password = byId("auth-password");
  const submit = byId("auth-submit");
  const authError = byId("auth-error");
  const focused = document.activeElement;
  const leavingAuth = authPanel.contains(focused);
  const leavingDashboard = dashboard.contains(focused) || logout === focused;
  const leavingRetry = byId("auth-retry") === focused;
  authError.hidden = true;
  form.hidden = false;
  byId("auth-retry").hidden = true;

  if (status.authenticated) {
    authPanel.hidden = true;
    dashboard.hidden = false;
    logout.hidden = false;
    setConnectionState("Authenticated", "loading");
    if (leavingAuth) byId("page-title").focus({ preventScroll: true });
    if (refresh) await refreshSnapshot();
    return;
  }

  dashboard.hidden = true;
  clearSnapshot("Sign in to view a current diagnostic snapshot.");
  clearGPTObservation("Sign in to run a manual GPT metadata observation.");
  clearPasswordFields();
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  logout.hidden = true;
  authPanel.hidden = false;
  form.dataset.mode = status.setup_required ? "setup" : "login";
  setText("auth-title", status.setup_required ? "Set up your administrator account." : "Sign in to PhantoWD.");
  setText("auth-description", status.setup_required ?
    "This initial account is stored in the configured system-state directory. Use at least 15 characters; a longer passphrase is better." :
    "Enter your local administrator credentials to view the system snapshot.");
  submit.textContent = status.setup_required ? "Create account" : "Sign in";
  password.autocomplete = status.setup_required ? "new-password" : "current-password";
  password.value = "";
  setConnectionState("Sign-in required");
  if (notice) setAuthError(notice);
  if (leavingDashboard || leavingRetry) byId("auth-title").focus({ preventScroll: true });
}

byId("auth-retry").addEventListener("click", async () => {
  retireAuthSubmission();
  retireAuthMutation();
  const retry = byId("auth-retry");
  retry.disabled = true;
  setConnectionState("Checking local API…", "loading");
  try {
    await updateAuthView();
  } catch {
    showAuthUnavailable();
  } finally {
    retry.disabled = false;
  }
});

let authSubmission = null;

function retireAuthSubmission() {
  const attempt = authSubmission;
  if (!attempt) return;
  authSubmission = null;
  clearTimeout(attempt.timeout);
  attempt.controller.abort();
  byId("auth-password").value = "";
  byId("auth-submit").disabled = false;
}

async function sendAuthCredentials(route, username, password, signal) {
  if (!signal || !["/api/v1/auth/setup", "/api/v1/auth/login"].includes(route)) throw new Error("Credential operation unavailable");
  const canceled = () => Object.assign(new Error("Credential submission canceled"), { name: "AbortError" });
  const read = async () => {
    const response = await fetch(route, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      credentials: "same-origin", cache: "no-store", signal,
      body: JSON.stringify({ username, password }),
    });
    if (signal.aborted || !response.ok) {
      try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch { /* preserve refusal */ }
      if (signal.aborted) throw canceled();
      const message = {
        400: "Check the username and password requirements.",
        401: "The username or password is not correct.",
        409: "Account setup is no longer available. Reload and sign in.",
        429: "Too many attempts. Wait one minute before trying again.",
      }[response.status];
      if (message) throw Object.assign(new Error(message), { authRefused: true });
      throw new Error("Credential outcome unavailable");
    }
    // Consume a bounded reply, but session authority comes only from the
    // subsequent status read. Response fields never grant a local session.
    await readDiagnosticJSON(response, 16 * 1024, signal);
  };
  // Fetch implementations may ignore cancellation, including before headers.
  // Keep late continuations handled without allowing them to update the UI.
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener("abort", abort); reject(canceled()); };
    if (signal.aborted) { abort(); return; }
    signal.addEventListener("abort", abort, { once: true });
    read().then(() => {
      signal.removeEventListener("abort", abort);
      if (signal.aborted) reject(canceled()); else resolve();
    }, failure => { signal.removeEventListener("abort", abort); reject(failure); });
  });
}

byId("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (authSubmission || authMutation) return;
  const form = byId("auth-form");
  const submit = byId("auth-submit");
  const error = byId("auth-error");
  const username = byId("auth-username").value;
  const password = byId("auth-password").value;
  const route = form.dataset.mode === "setup" ? "/api/v1/auth/setup" : "/api/v1/auth/login";
  if (route === "/api/v1/auth/setup" && [...password].length < 15) {
    setAuthError("Use a passphrase with at least 15 characters.");
    return;
  }
  if (new TextEncoder().encode(password).length > 1024) {
    setAuthError("The password is longer than the 1024-byte limit.");
    return;
  }
  submit.disabled = true;
  error.hidden = true;
  const controller = new AbortController();
  const attempt = { controller, timeout: setTimeout(() => controller.abort(), 10000) };
  authSubmission = attempt;
  const owns = () => authSubmission === attempt;
  const current = () => owns() && !controller.signal.aborted;
  let authenticated = false;
  try {
    await sendAuthCredentials(route, username, password, controller.signal);
    if (!current()) return;
    byId("auth-password").value = "";
    await updateAuthView({ refresh: false, current, signal: controller.signal });
    authenticated = current() && !byId("dashboard-content").hidden;
  } catch (failure) {
    if (!owns()) return;
    if (!controller.signal.aborted && failure?.authRefused === true) setAuthError(failure.message);
    else {
      showAuthUnavailable();
      setAuthError("Sign-in or setup outcome could not be confirmed. The request was not retried. Retry connection to check current status before submitting credentials again; account setup may already have completed.");
    }
  } finally {
    if (owns()) retireAuthSubmission();
    else { clearTimeout(attempt.timeout); controller.abort(); }
  }
  // Diagnostic loading has its existing separate bounded snapshot lifetime;
  // it cannot keep the credential form busy or extend its ten-second budget.
  if (authenticated) await refreshSnapshot();
});

let authMutation = null;

function retireAuthMutation() {
  const attempt = authMutation;
  if (!attempt) return;
  authMutation = null;
  clearTimeout(attempt.timeout);
  attempt.controller.abort();
  clearPasswordFields();
  for (const id of ["password-submit", "logout", "logout-all"]) byId(id).disabled = false;
}

function beginAuthMutation() {
  retireAuthSubmission();
  const controller = new AbortController();
  const attempt = { controller, timeout: setTimeout(() => controller.abort(), 10000) };
  authMutation = attempt;
  for (const id of ["password-submit", "logout", "logout-all"]) byId(id).disabled = true;
  return attempt;
}

function finishAuthMutation(attempt) {
  if (authMutation === attempt) retireAuthMutation();
  else { clearTimeout(attempt.timeout); attempt.controller.abort(); }
}

async function readAuthMutationReply(path, signal, { csrf, body } = {}) {
  const method = path === "/api/v1/auth/session" ? "GET" :
    ["/api/v1/auth/logout", "/api/v1/auth/logout-all", "/api/v1/auth/password"].includes(path) ? "POST" : null;
  if (!method || !signal || (method === "POST" && (typeof csrf !== "string" || csrf.length !== 43))) throw new Error("Session operation unavailable");
  const canceled = () => Object.assign(new Error("Session operation canceled"), { name: "AbortError" });
  const read = async () => {
    const response = await fetch(path, {
      method, headers: { Accept: "application/json", ...(csrf ? { "X-PhantoWD-CSRF": csrf } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
      credentials: "same-origin", cache: "no-store", signal,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (signal.aborted || (!response.ok && path !== "/api/v1/auth/password")) {
      try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch { /* preserve fixed refusal */ }
      throw signal.aborted ? canceled() : new Error("Session operation unavailable");
    }
    const value = await readDiagnosticJSON(response, 16 * 1024, signal);
    return { ok: response.ok, status: response.status, value };
  };
  // Includes pre-header waits even when an underlying transport ignores abort.
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener("abort", abort); reject(canceled()); };
    if (signal.aborted) { abort(); return; }
    signal.addEventListener("abort", abort, { once: true });
    read().then(value => {
      signal.removeEventListener("abort", abort);
      if (signal.aborted) reject(canceled()); else resolve(value);
    }, failure => { signal.removeEventListener("abort", abort); reject(failure); });
  });
}

async function signOut(all = false) {
  if (authMutation) return;
  const attempt = beginAuthMutation();
  const signal = attempt.controller.signal;
  const current = () => authMutation === attempt && !signal.aborted;
  clearSnapshot("Signing out. Previous diagnostic observations were cleared.");
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  clearPasswordFields();
  try {
    const session = await readAuthMutationReply("/api/v1/auth/session", signal);
    if (!current()) return;
    const response = await readAuthMutationReply(all ? "/api/v1/auth/logout-all" : "/api/v1/auth/logout", signal, { csrf: session.value?.csrf_token });
    if (!current()) return;
    if (response.value?.[all ? "all_panel_sessions_revoked" : "logged_out"] !== true) throw new Error("Session termination unconfirmed");
    await updateAuthView({ refresh: false, current, signal, requireSignedOut: true });
  } catch {
    if (authMutation !== attempt) return;
    showAuthUnavailable();
    setAuthError("Sign-out outcome could not be confirmed. Check connection status before signing in again; the request was not retried.");
  } finally {
    finishAuthMutation(attempt);
  }
}
byId("logout").addEventListener("click", () => signOut(false));
byId("logout-all").addEventListener("click", () => signOut(true));

function clearPasswordFields() {
  for (const id of ["password-current", "password-new", "password-confirm"]) byId(id).value = "";
}

byId("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (authMutation) return;
  const currentPassword = byId("password-current").value;
  const newPassword = byId("password-new").value;
  const confirmation = byId("password-confirm").value;
  if (!currentPassword || [...newPassword].length < 15 || newPassword !== confirmation || newPassword === currentPassword ||
      [currentPassword, newPassword].some((p) => new TextEncoder().encode(p).length > 1024)) {
    setText("password-status", "Check the current password, use a different new passphrase of 15+ characters (at most 1024 UTF-8 bytes), and repeat it exactly.");
    return;
  }
  const attempt = beginAuthMutation();
  const signal = attempt.controller.signal;
  const current = () => authMutation === attempt && !signal.aborted;
  clearSnapshot("Changing credentials. Previous diagnostic observations were cleared.");
  clearPasswordFields();
  clearServicePolicy();
  clearSavedPolicy();
  clearPolicyDraft();
  setText("password-status", "Verifying and saving the new password…");
  try {
    const session = await readAuthMutationReply("/api/v1/auth/session", signal);
    if (!current()) return;
    const response = await readAuthMutationReply("/api/v1/auth/password", signal, {
      csrf: session.value?.csrf_token, body: { current_password: currentPassword, new_password: newPassword },
    });
    if (!current()) return;
    const result = response.value;
    if (!response.ok) {
      const message = response.status === 401 && result?.error === "current_password_invalid" ? "Current password is not correct. No password was changed." :
        response.status === 422 && result?.error === "new_password_invalid" ? "The new password does not meet the requirements. No password was changed." :
          response.status === 429 && result?.error === "password_change_rate_limited" ? "Too many attempts. Wait one minute before trying again." : "";
      if (message) { setText("password-status", message); return; }
      throw new Error("Unconfirmed password change");
    }
    if (result?.password_changed !== true || result?.reauthentication_required !== true || result?.all_panel_sessions_revoked !== true) {
      throw new Error("Invalid confirmation");
    }
    await updateAuthView({ refresh: false, current, signal, requireSignedOut: true, notice: "Password changed. All panel sessions ended. Sign in with the new password." });
  } catch {
    if (authMutation !== attempt) return;
    showAuthUnavailable();
    setAuthError("Password-change outcome could not be confirmed. Do not repeat it automatically: reconnect and check sign-in with the new password first. If account storage is unavailable, stop and reconcile it. The request was not retried.");
  } finally {
    finishAuthMutation(attempt);
  }
});

// Deferred after app.js: shared UI helpers exist before authentication starts.
updateAuthView().catch(showAuthUnavailable);
