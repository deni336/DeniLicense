const API = "/api/v1";
const SESSION_KEYS = {
  access: "denilicense.accessToken",
  accessExpiry: "denilicense.accessExpiresAt",
  refresh: "denilicense.refreshToken",
  refreshExpiry: "denilicense.refreshExpiresAt",
  user: "denilicense.user",
};

const state = {
  accessToken: sessionStorage.getItem(SESSION_KEYS.access) || "",
  accessExpiresAt: sessionStorage.getItem(SESSION_KEYS.accessExpiry) || "",
  refreshToken: sessionStorage.getItem(SESSION_KEYS.refresh) || "",
  refreshExpiresAt: sessionStorage.getItem(SESSION_KEYS.refreshExpiry) || "",
  user: readStoredUser(),
  products: [],
  licenses: [],
  requests: [],
  machines: [],
  issuers: [],
  accountSessions: [],
  auditItems: [],
  auditCursor: null,
  route: "dashboard",
  drawerReturnFocus: null,
};

const routes = {
  dashboard: { title: "Overview", kicker: "Operations", roles: null },
  licenses: { title: "Licenses", kicker: "Inventory", roles: null },
  requests: { title: "License requests", kicker: "Fulfillment", roles: null },
  machines: {
    title: "Machines",
    kicker: "Installations",
    roles: ["platform_owner", "license_admin", "support", "auditor"],
  },
  products: {
    title: "Products",
    kicker: "Catalog",
    roles: ["platform_owner", "license_admin", "support", "auditor"],
  },
  issuers: { title: "Issuers", kicker: "Trust store", roles: ["platform_owner"] },
  users: { title: "Users", kicker: "Access control", roles: ["platform_owner"] },
  audit: {
    title: "Audit log",
    kicker: "Accountability",
    roles: ["platform_owner", "auditor"],
  },
};

const ROLE_ORDER = ["platform_owner", "license_admin", "support", "auditor", "customer"];
const ROLE_PROFILES = Object.freeze({
  platform_owner: {
    label: "Platform owner",
    summary: "Complete control of security, trust, licensing, and user access.",
    permissions: [
      "Create users and assign every role",
      "Register and revoke offline issuer keys",
      "Issue, import, suspend, and revoke licenses",
      "Review customer requests and archive records",
      "Manage products and machine activations",
      "Read the complete audit log",
    ],
  },
  license_admin: {
    label: "License admin",
    summary: "Runs the license catalog and day-to-day issuance operations.",
    permissions: [
      "View all license owners, licenses, and machines",
      "Issue and import licenses",
      "Review and fulfill customer license requests",
      "Suspend or revoke licenses",
      "Create, retire, and reactivate products",
      "Deactivate machine activations",
    ],
  },
  support: {
    label: "Support",
    summary: "Investigates customer and machine issues without issuance access.",
    permissions: [
      "View all license owners and licenses",
      "View machine activation details",
      "View product catalog and lifecycle status",
      "Deactivate machine activations",
      "View operational dashboard totals",
    ],
  },
  auditor: {
    label: "Auditor",
    summary: "Read-only oversight of licensing activity and security events.",
    permissions: [
      "View all licenses and machines",
      "View product catalog and lifecycle status",
      "View operational dashboard totals",
      "Read the complete audit log",
      "No administrative mutations",
    ],
  },
  customer: {
    label: "Customer",
    summary: "Self-service access limited to licenses assigned to this account.",
    permissions: [
      "View and claim own licenses",
      "Request licenses and track fulfillment",
      "Activate licensed machines",
      "View and deactivate own activations",
      "No administrative access",
    ],
  },
});

let refreshPromise = null;
let routeRequest = 0;
let passwordSetupToken = "";
let emailVerificationToken = "";
let registrationOpen = false;
let passwordMinCharacters = 15;
const listRequests = {
  licenses: 0,
  requests: 0,
  machines: 0,
  products: 0,
  issuers: 0,
  users: 0,
  sessions: 0,
};
const mobileNavigation = window.matchMedia("(max-width: 820px)");

function byId(id) {
  return document.getElementById(id);
}

function readStoredUser() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEYS.user) || "null");
  } catch {
    return null;
  }
}

function make(tag, options = {}) {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.text !== undefined && options.text !== null) {
    element.textContent = String(options.text);
  }
  if (options.title) element.title = options.title;
  if (options.type) element.type = options.type;
  if (options.name) element.name = options.name;
  if (options.value !== undefined) element.value = options.value;
  if (options.hidden) element.hidden = true;
  if (options.disabled) element.disabled = true;
  if (options.attributes) {
    for (const [name, value] of Object.entries(options.attributes)) {
      element.setAttribute(name, value);
    }
  }
  return element;
}

function append(parent, ...children) {
  for (const child of children) {
    if (child !== null && child !== undefined) parent.append(child);
  }
  return parent;
}

function makeButton(text, className = "button secondary", action = null) {
  const button = make("button", { className, text, type: "button" });
  if (action) button.addEventListener("click", action);
  return button;
}

function badge(value) {
  const normalized = String(value || "unknown").toLowerCase().replaceAll(" ", "_");
  return make("span", {
    className: `badge ${normalized}`,
    text: String(value || "Unknown").replaceAll("_", " "),
  });
}

function roleProfile(role) {
  return ROLE_PROFILES[role] || {
    label: String(role || "Unknown role").replaceAll("_", " "),
    summary: "The server returned a role this console does not recognize.",
    permissions: [],
  };
}

function populateRoleSelect(select, selected = "license_admin") {
  select.replaceChildren();
  for (const role of ROLE_ORDER) {
    select.append(make("option", { value: role, text: roleProfile(role).label }));
  }
  select.value = ROLE_PROFILES[selected] ? selected : "license_admin";
}

function renderPermissionPreview(container, role, heading = "Effective permissions") {
  const profile = roleProfile(role);
  const header = make("div", { className: "permission-preview-header" });
  const copy = make("div");
  append(copy, make("strong", { text: `${heading}: ${profile.label}` }), make("p", { text: profile.summary }));
  append(header, copy, make("span", { className: `badge ${role}`, text: profile.label }));
  const list = make("ul", { className: "permission-list" });
  for (const permission of profile.permissions) list.append(make("li", { text: permission }));
  container.replaceChildren(header, list);
}

function renderRoleGuide() {
  const guide = byId("role-guide");
  if (!guide) return;
  const cards = ROLE_ORDER.map((role) => {
    const profile = roleProfile(role);
    const card = make("article", { className: "role-summary" });
    const list = make("ul", { className: "role-mini-list" });
    for (const permission of profile.permissions) list.append(make("li", { text: permission }));
    append(
      card,
      make("h4", { text: profile.label }),
      make("p", { text: profile.summary }),
      make("span", { className: "role-count", text: `${profile.permissions.length} capabilities` }),
      list,
    );
    return card;
  });
  guide.replaceChildren(...cards);
}

function formatDate(value, includeTime = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    ...(includeTime ? { timeStyle: "short" } : {}),
  }).format(date);
}

function formatDuration(seconds) {
  const value = Number(seconds || 0);
  if (value % 86400 === 0) return `${value / 86400} days`;
  if (value % 3600 === 0) return `${value / 3600} hours`;
  return `${value} seconds`;
}

function shortId(value, length = 12) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length)}…` : text || "—";
}

function setError(element, error) {
  if (!error) {
    element.hidden = true;
    element.textContent = "";
    return;
  }
  const request = error.requestId ? ` Request ID: ${error.requestId}.` : "";
  element.textContent = `${error.message || "The request failed."}${request}`;
  element.hidden = false;
}

function loading(container, label = "Loading…") {
  container.replaceChildren(make("div", {
    className: "loading-state",
    text: label,
    attributes: { role: "status", "aria-live": "polite", "aria-busy": "true" },
  }));
}

function empty(container, title, description) {
  const wrapper = make("div", { className: "empty-state" });
  const content = make("div");
  append(content, make("strong", { text: title }), make("span", { text: description }));
  wrapper.append(content);
  container.replaceChildren(wrapper);
}

function toast(message, kind = "success") {
  const item = make("div", {
    className: `toast ${kind === "error" ? "error" : ""}`,
    text: message,
    attributes: { role: kind === "error" ? "alert" : "status" },
  });
  byId("toast-region").append(item);
  window.setTimeout(() => item.remove(), 5200);
}

class APIProblem extends Error {
  constructor(problem, status) {
    super(problem.detail || problem.title || `Request failed with status ${status}.`);
    this.name = "APIProblem";
    this.status = status;
    this.code = problem.code || "request_failed";
    this.requestId = problem.requestId || "";
  }
}

function storeSession(payload) {
  if (payload.accessToken) state.accessToken = payload.accessToken;
  if (payload.accessExpiresAt) state.accessExpiresAt = payload.accessExpiresAt;
  if (payload.refreshToken) state.refreshToken = payload.refreshToken;
  if (payload.refreshExpiresAt) state.refreshExpiresAt = payload.refreshExpiresAt;
  if (payload.user) state.user = payload.user;
  sessionStorage.setItem(SESSION_KEYS.access, state.accessToken);
  sessionStorage.setItem(SESSION_KEYS.accessExpiry, state.accessExpiresAt);
  sessionStorage.setItem(SESSION_KEYS.refresh, state.refreshToken);
  sessionStorage.setItem(SESSION_KEYS.refreshExpiry, state.refreshExpiresAt);
  if (state.user) sessionStorage.setItem(SESSION_KEYS.user, JSON.stringify(state.user));
}

function clearSession() {
  state.accessToken = "";
  state.accessExpiresAt = "";
  state.refreshToken = "";
  state.refreshExpiresAt = "";
  state.user = null;
  state.products = [];
  state.licenses = [];
  state.requests = [];
  state.machines = [];
  state.accountSessions = [];
  passwordSetupToken = "";
  for (const key of Object.values(SESSION_KEYS)) sessionStorage.removeItem(key);
  clearClaimCode();
  clearUserInviteResult();
  for (const id of [
    "user-dialog",
    "user-invite-result-dialog",
    "password-reset-request-dialog",
    "registration-dialog",
    "license-request-dialog",
    "claim-license-dialog",
    "account-security-dialog",
  ]) {
    const dialog = byId(id);
    if (dialog?.open) dialog.close();
  }
}

async function parseResponse(response) {
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("json")) {
    if (!response.ok) throw new APIProblem({}, response.status);
    return null;
  }
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new APIProblem({ detail: "The server returned an unreadable response." }, response.status);
  }
  if (!response.ok) throw new APIProblem(payload, response.status);
  return payload;
}

async function refreshSession() {
  if (refreshPromise) return refreshPromise;
  if (!state.refreshToken) throw new APIProblem({ detail: "Your session has ended." }, 401);
  refreshPromise = (async () => {
    const response = await fetch(`${API}/auth/refresh`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: state.refreshToken }),
      credentials: "same-origin",
      cache: "no-store",
    });
    try {
      const payload = await parseResponse(response);
      storeSession(payload);
      return payload;
    } catch (error) {
      clearSession();
      showLogin("Your session ended. Sign in again.");
      throw error;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

async function api(path, options = {}, retry = true) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (state.accessToken) headers.set("Authorization", `Bearer ${state.accessToken}`);
  let body = options.body;
  if (body !== undefined && body !== null && typeof body !== "string") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    ...options,
    body,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 401 && retry && state.refreshToken) {
    await refreshSession();
    return api(path, options, false);
  }
  return parseResponse(response);
}

function roleAllowed(route) {
  const definition = routes[route];
  return Boolean(definition && (!definition.roles || definition.roles.includes(state.user?.role)));
}

function hasRole(...roles) {
  return roles.includes(state.user?.role);
}

function isManagementReader() {
  return hasRole("platform_owner", "license_admin", "support", "auditor");
}

function isLicenseWriter() {
  return hasRole("platform_owner", "license_admin");
}

function isCustomer() {
  return hasRole("customer");
}

function canDeactivate() {
  return hasRole("platform_owner", "license_admin", "support", "customer");
}

function showLogin(message = "") {
  emailVerificationToken = "";
  closeDrawer();
  setSidebarOpen(false, false);
  byId("app-shell").hidden = true;
  byId("password-setup-screen").hidden = true;
  byId("email-verification-screen").hidden = true;
  byId("login-screen").hidden = false;
  byId("open-registration-button").hidden = !registrationOpen;
  setError(byId("login-error"), message ? new Error(message) : null);
  window.setTimeout(() => byId("login-email").focus(), 0);
}

function showApp() {
  byId("login-screen").hidden = true;
  byId("password-setup-screen").hidden = true;
  byId("email-verification-screen").hidden = true;
  byId("app-shell").hidden = false;
  const email = state.user?.email || "Account";
  byId("user-email").textContent = email;
  byId("user-role").textContent = (state.user?.role || "").replaceAll("_", " ");
  byId("user-avatar").textContent = email.slice(0, 2).toUpperCase();
  for (const button of document.querySelectorAll("[data-roles]")) {
    const rolesForButton = button.dataset.roles.split(",");
    button.hidden = !rolesForButton.includes(state.user?.role);
  }
  byId("license-actions").hidden = !isLicenseWriter() && !isCustomer();
  byId("create-license-button").hidden = !isLicenseWriter();
  byId("import-license-button").hidden = !isLicenseWriter();
  byId("claim-license-button").hidden = !isCustomer();
  byId("license-filters").hidden = !isManagementReader();
  byId("license-lifecycle-console").hidden = !isManagementReader();
  byId("create-request-button").hidden = !isCustomer();
  byId("request-filters").hidden = !isManagementReader();
  byId("create-product-button").hidden = !isLicenseWriter();
  for (const control of document.querySelectorAll("[data-owner-only]")) {
    control.hidden = !hasRole("platform_owner");
  }
  const licenseLifecycle = byId("license-filters").elements.lifecycle;
  for (const option of licenseLifecycle.options) {
    if (!["deleted", "all"].includes(option.value)) continue;
    option.hidden = !hasRole("platform_owner");
    option.disabled = !hasRole("platform_owner");
  }
  if (licenseLifecycle.selectedOptions[0]?.disabled) licenseLifecycle.value = "current";
  byId("requests-heading").textContent = isCustomer() ? "My license requests" : "License requests";
  byId("requests-description").textContent = isCustomer()
    ? "Request access to a product and track approval or fulfillment from one place."
    : "Review customer requests and issue licenses with explicit product entitlements.";
  setSidebarOpen(false, false);
  checkHealth();
}

function takePasswordSetupIntent() {
  const url = new URL(window.location.href);
  const resetPath = url.pathname.replace(/\/+$/, "") === "/reset-password";
  const resetAction = url.searchParams.get("action") === "reset-password";
  if (!resetPath && !resetAction) return { requested: false, token: "" };
  const token = String(url.searchParams.get("token") || "").trim();
  history.replaceState(null, "", "/ui/");
  return { requested: true, token };
}

function takeEmailVerificationIntent() {
  const url = new URL(window.location.href);
  const verificationPath = url.pathname.replace(/\/+$/, "") === "/verify-email";
  const verificationAction = url.searchParams.get("action") === "verify-email";
  if (!verificationPath && !verificationAction) return { requested: false, token: "" };
  const token = String(url.searchParams.get("token") || "").trim();
  history.replaceState(null, "", "/ui/");
  return { requested: true, token };
}

async function loadPublicConfig() {
  try {
    const payload = await api(`${API}/public/config`, {}, false);
    registrationOpen = payload?.registrationOpen === true;
    const configuredMinimum = Number(payload?.passwordMinCharacters);
    if (Number.isInteger(configuredMinimum) && configuredMinimum > 0 && configuredMinimum <= 1024) {
      passwordMinCharacters = configuredMinimum;
      for (const input of document.querySelectorAll('input[name="newPassword"], input[name="confirmPassword"]')) {
        input.minLength = passwordMinCharacters;
      }
    }
  } catch (error) {
    if (error.status !== 404 && error.status !== 405) {
      console.warn("Unable to read public registration configuration.");
    }
    registrationOpen = false;
  }
  byId("open-registration-button").hidden = !registrationOpen || !byId("app-shell").hidden;
}

function showEmailVerification(token) {
  closeDrawer();
  setSidebarOpen(false, false);
  byId("login-screen").hidden = true;
  byId("password-setup-screen").hidden = true;
  byId("app-shell").hidden = true;
  byId("email-verification-screen").hidden = false;
  const status = byId("email-verification-status");
  const form = byId("email-verification-form");
  const continueButton = byId("email-verification-continue");
  form.reset();
  setError(byId("email-verification-error"), null);
  continueButton.hidden = true;
  emailVerificationToken = token;
  if (!token) {
    status.textContent = "The verification link is incomplete.";
    form.hidden = true;
    setError(
      byId("email-verification-error"),
      new Error("This email verification link is missing its one-time token. Open the complete link from your email."),
    );
    continueButton.hidden = false;
    return;
  }
  form.hidden = false;
  status.textContent = "Choose a password to verify your email and activate your customer account.";
  window.setTimeout(() => form.elements.newPassword.focus(), 0);
}

async function completeEmailVerification(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const password = String(data.get("newPassword") || "");
  const confirmation = String(data.get("confirmPassword") || "");
  const status = byId("email-verification-status");
  const continueButton = byId("email-verification-continue");
  setError(byId("email-verification-error"), null);
  if (password !== confirmation) {
    setError(byId("email-verification-error"), new Error("The passwords do not match."));
    form.elements.confirmPassword.focus();
    return;
  }
  if (!emailVerificationToken) {
    setError(byId("email-verification-error"), new Error("This verification link is no longer available. Open the link from your latest email."));
    form.hidden = true;
    continueButton.hidden = false;
    return;
  }
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  submit.classList.add("loading");
  try {
    const payload = await api(`${API}/auth/verify-email`, {
      method: "POST",
      body: { token: emailVerificationToken, newPassword: password },
    }, false);
    emailVerificationToken = "";
    form.reset();
    form.hidden = true;
    const email = payload?.user?.email ? ` for ${payload.user.email}` : "";
    if (payload?.user?.email) byId("login-email").value = payload.user.email;
    status.textContent = `Email verified${email}. Your customer account is active and ready to sign in.`;
    continueButton.hidden = false;
    window.setTimeout(() => continueButton.focus(), 0);
  } catch (error) {
    status.textContent = "Account setup was not completed.";
    setError(byId("email-verification-error"), error);
  } finally {
    submit.disabled = false;
    submit.classList.remove("loading");
  }
}

function showPasswordSetup(token) {
  closeDrawer();
  setSidebarOpen(false, false);
  byId("login-screen").hidden = true;
  byId("email-verification-screen").hidden = true;
  byId("app-shell").hidden = true;
  byId("password-setup-screen").hidden = false;
  byId("password-setup-entry").hidden = false;
  byId("password-setup-complete").hidden = true;
  const form = byId("password-setup-form");
  form.hidden = !token;
  setError(byId("password-setup-error"), token ? null : new Error("This password setup link is missing its one-time token. Open the complete invitation link again."));
  if (token) window.setTimeout(() => form.elements.newPassword.focus(), 0);
}

async function completePasswordSetup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const password = String(data.get("newPassword") || "");
  const confirmation = String(data.get("confirmPassword") || "");
  setError(byId("password-setup-error"), null);
  if (password !== confirmation) {
    setError(byId("password-setup-error"), new Error("The passwords do not match."));
    form.elements.confirmPassword.focus();
    return;
  }
  const token = passwordSetupToken;
  passwordSetupToken = "";
  if (!token) {
    setError(byId("password-setup-error"), new Error("This setup link is no longer available. Open the original invitation link again."));
    return;
  }
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  submit.classList.add("loading");
  try {
    await api(`${API}/auth/password-reset/confirm`, { method: "POST", body: { token, newPassword: password } }, false);
    form.reset();
    byId("password-setup-entry").hidden = true;
    byId("password-setup-complete").hidden = false;
    window.setTimeout(() => byId("password-setup-continue").focus(), 0);
  } catch (error) {
    setError(byId("password-setup-error"), new Error(`${error.message} Open the invitation link again to retry, or ask an administrator for a new invitation.`));
    for (const field of form.elements) field.disabled = true;
  } finally {
    submit.classList.remove("loading");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const formData = new FormData(form);
  setError(byId("login-error"), null);
  submit.disabled = true;
  submit.classList.add("loading");
  try {
    const response = await fetch(`${API}/auth/login`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ email: formData.get("email"), password: formData.get("password") }),
      credentials: "same-origin",
      cache: "no-store",
    });
    const payload = await parseResponse(response);
    storeSession(payload);
    if (payload?.user?.emailVerifiedAt === null) {
      const email = payload.user.email || String(formData.get("email") || "");
      clearSession();
      byId("login-email").value = email;
      showLogin("Verify your email and choose a password before signing in. You can request a fresh verification email below.");
      return;
    }
    form.reset();
    showApp();
    navigate(location.hash.slice(1) || "dashboard", true);
  } catch (error) {
    if (error.code === "email_verification_required") {
      setError(byId("login-error"), new Error("Verify your email before signing in. You can request a fresh verification email below."));
      byId("resend-verification-button").focus();
    } else {
      setError(byId("login-error"), error);
    }
  } finally {
    submit.disabled = false;
    submit.classList.remove("loading");
  }
}

function openRegistrationDialog() {
  if (!registrationOpen) {
    toast("Customer registration is currently closed.", "error");
    return;
  }
  const form = byId("registration-form");
  form.reset();
  setError(byId("registration-error"), null);
  byId("registration-entry").hidden = false;
  byId("registration-complete").hidden = true;
  byId("development-verification-fields").hidden = true;
  byId("development-verification-link").textContent = "";
  byId("registration-submit").hidden = false;
  form.elements.registrationEmail.value = byId("login-email").value.trim();
  byId("registration-dialog").showModal();
  window.setTimeout(() => form.elements.registrationEmail.focus(), 0);
}

async function registerCustomer(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = byId("registration-submit");
  const data = new FormData(form);
  const email = String(data.get("registrationEmail") || "").trim();
  setError(byId("registration-error"), null);
  submit.disabled = true;
  try {
    const payload = await api(`${API}/auth/register`, { method: "POST", body: { email } }, false);
    byId("registration-entry").hidden = true;
    byId("registration-complete").hidden = false;
    submit.hidden = true;
    byId("registration-result-message").textContent =
      "If this address can be registered, a one-time verification link has been queued. Verify the email before signing in.";
    const token = String(payload?.developmentVerificationToken || "");
    if (token) {
      const verification = new URL("/verify-email", window.location.origin);
      verification.searchParams.set("token", token);
      byId("development-verification-link").textContent = verification.toString();
      byId("development-verification-fields").hidden = false;
    }
    byId("login-email").value = email;
    window.setTimeout(() => byId("registration-dialog").querySelector('[data-close-dialog="registration-dialog"]').focus(), 0);
  } catch (error) {
    setError(byId("registration-error"), error);
  } finally {
    submit.disabled = false;
  }
}

async function resendVerification() {
  const email = byId("login-email").value.trim();
  if (!email || !byId("login-email").checkValidity()) {
    byId("login-email").reportValidity();
    byId("login-email").focus();
    return;
  }
  const button = byId("resend-verification-button");
  setError(byId("login-error"), null);
  button.disabled = true;
  try {
    const payload = await api(`${API}/auth/verification/request`, { method: "POST", body: { email } }, false);
    toast("If the account is awaiting verification, a new email has been queued.");
    const token = String(payload?.developmentVerificationToken || "");
    if (token) {
      const verification = new URL("/verify-email", window.location.origin);
      verification.searchParams.set("token", token);
      const dialog = byId("registration-dialog");
      byId("registration-entry").hidden = true;
      byId("registration-complete").hidden = false;
      byId("registration-submit").hidden = true;
      byId("registration-result-message").textContent = "A replacement verification link was created for this account.";
      byId("development-verification-link").textContent = verification.toString();
      byId("development-verification-fields").hidden = false;
      dialog.showModal();
    }
  } catch (error) {
    setError(byId("login-error"), error);
  } finally {
    button.disabled = false;
  }
}

async function copyVerificationLink() {
  const link = byId("development-verification-link").textContent;
  if (!link) return;
  try {
    await navigator.clipboard.writeText(link);
    toast("Email verification link copied.");
  } catch {
    toast("Clipboard access is unavailable. Select and copy the displayed link.", "error");
  }
}

async function logout() {
  try {
    if (state.accessToken) await api(`${API}/auth/logout`, { method: "POST" }, false);
  } catch {
    // Local sign-out must remain available during outages.
  }
  clearSession();
  showLogin();
}

function openAccountSecurity() {
  const dialog = byId("account-security-dialog");
  const form = byId("account-password-form");
  form.reset();
  setError(byId("account-password-error"), null);
  setError(byId("account-sessions-error"), null);
  const status = byId("account-password-status");
  status.hidden = true;
  status.textContent = "";
  dialog.showModal();
  loadAccountSessions();
  window.setTimeout(() => form.elements.currentPassword.focus(), 0);
}

async function loadAccountSessions() {
  const request = ++listRequests.sessions;
  const container = byId("account-sessions");
  setError(byId("account-sessions-error"), null);
  loading(container, "Loading active sessions…");
  try {
    const payload = await api(`${API}/auth/sessions`);
    if (request !== listRequests.sessions) return;
    state.accountSessions = payload.items || [];
    renderAccountSessions(container, state.accountSessions);
  } catch (error) {
    if (request !== listRequests.sessions) return;
    state.accountSessions = [];
    setError(byId("account-sessions-error"), error);
    empty(container, "Sessions unavailable", "Refresh to try loading your active sessions again.");
    byId("revoke-other-sessions").disabled = true;
  }
}

function renderAccountSessions(container, sessions) {
  const revokeOthers = byId("revoke-other-sessions");
  revokeOthers.disabled = !sessions.some((session) => !session.isCurrent);
  if (!sessions.length) {
    empty(container, "No active sessions", "No session records were returned for this account.");
    return;
  }
  const cards = [];
  const ordered = [...sessions].sort((left, right) => Number(right.isCurrent) - Number(left.isCurrent));
  for (const session of ordered) {
    const card = make("article", { className: "session-card" });
    const head = make("div", { className: "session-card-heading" });
    const title = make("div");
    append(
      title,
      make("h4", { text: session.isCurrent ? "Current browser session" : "Signed-in session" }),
      make("span", { className: "mono muted", text: shortId(session.id, 22), title: session.id }),
    );
    append(head, title, badge(session.isCurrent ? "current" : "active"));
    const details = make("dl", { className: "session-details" });
    append(
      details,
      detailField("Created", formatDate(session.createdAt)),
      detailField("Last activity", formatDate(session.lastSeenAt)),
      detailField("Access expires", formatDate(session.accessExpiresAt)),
      detailField("Refresh expires", formatDate(session.refreshExpiresAt)),
    );
    const actionLabel = session.isCurrent ? "Revoke and sign out" : "Revoke session";
    const revoke = makeButton(actionLabel, "button danger-outline", () => revokeAccountSession(session));
    revoke.setAttribute("aria-label", `${actionLabel} ${shortId(session.id, 12)}`);
    append(card, head, details, revoke);
    cards.push(card);
  }
  container.replaceChildren(...cards);
}

async function changeOwnPassword(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const currentPassword = String(data.get("currentPassword") || "");
  const newPassword = String(data.get("newPassword") || "");
  const confirmation = String(data.get("confirmPassword") || "");
  const errorElement = byId("account-password-error");
  const status = byId("account-password-status");
  setError(errorElement, null);
  status.hidden = true;
  status.textContent = "";
  if (newPassword.length < passwordMinCharacters) {
    setError(errorElement, new Error(`Use at least ${passwordMinCharacters} characters for the new password.`));
    form.elements.newPassword.focus();
    return;
  }
  if (newPassword !== confirmation) {
    setError(errorElement, new Error("The new passwords do not match."));
    form.elements.confirmPassword.focus();
    return;
  }
  if (newPassword === currentPassword) {
    setError(errorElement, new Error("Choose a new password that differs from the current password."));
    form.elements.newPassword.focus();
    return;
  }
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  submit.classList.add("loading");
  try {
    await api(`${API}/auth/password/change`, {
      method: "POST",
      body: { currentPassword, newPassword },
    });
    form.reset();
    status.textContent = "Password changed. Every other active session has been revoked.";
    status.hidden = false;
    toast("Password changed and other sessions revoked.");
    await loadAccountSessions();
  } catch (error) {
    setError(errorElement, error);
  } finally {
    submit.disabled = false;
    submit.classList.remove("loading");
  }
}

async function revokeOtherSessions() {
  const count = state.accountSessions.filter((session) => !session.isCurrent).length;
  if (!count) {
    toast("There are no other sessions to revoke.");
    return;
  }
  const confirmed = await confirmAction(
    "Revoke every other session?",
    `${count} other session${count === 1 ? "" : "s"} will be signed out. This browser will remain signed in.`,
    "Revoke other sessions",
  );
  if (!confirmed) return;
  const button = byId("revoke-other-sessions");
  button.disabled = true;
  try {
    await api(`${API}/auth/sessions/revoke-others`, { method: "POST" });
    toast("Other sessions revoked.");
    await loadAccountSessions();
  } catch (error) {
    setError(byId("account-sessions-error"), error);
  } finally {
    button.disabled = !state.accountSessions.some((session) => !session.isCurrent);
  }
}

async function revokeAccountSession(session) {
  const current = session.isCurrent === true;
  const confirmed = await confirmAction(
    current ? "Revoke this browser session?" : "Revoke this session?",
    current
      ? "This browser will be signed out immediately. Unsaved form changes will be lost."
      : "The selected session will be unable to refresh or continue authenticated access.",
    current ? "Revoke and sign out" : "Revoke session",
  );
  if (!confirmed) return;
  try {
    await api(`${API}/auth/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
    if (current) {
      clearSession();
      showLogin("This browser session was revoked. Sign in again to continue.");
      return;
    }
    toast("Session revoked.");
    await loadAccountSessions();
  } catch (error) {
    setError(byId("account-sessions-error"), error);
  }
}

async function checkHealth() {
  const dot = byId("system-indicator");
  const label = byId("system-status");
  dot.className = "health-dot";
  label.textContent = "Checking…";
  try {
    const response = await fetch("/ready", { cache: "no-store" });
    if (!response.ok) throw new Error();
    dot.classList.add("healthy");
    label.textContent = "Operational";
  } catch {
    dot.classList.add("unhealthy");
    label.textContent = "Unavailable";
  }
}

function navigate(route, replace = false) {
  let target = routes[route] ? route : "dashboard";
  if (!roleAllowed(target)) target = "dashboard";
  if (location.hash !== `#${target}`) {
    if (replace) history.replaceState(null, "", `#${target}`);
    else {
      location.hash = target;
      return;
    }
  }
  state.route = target;
  for (const view of document.querySelectorAll("[data-view]")) {
    view.hidden = view.dataset.view !== target;
  }
  for (const button of document.querySelectorAll("[data-route]")) {
    const active = button.dataset.route === target;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  byId("page-title").textContent = routes[target].title;
  byId("page-kicker").textContent = routes[target].kicker;
  setSidebarOpen(false, false);
  byId("main-content").focus({ preventScroll: true });
  loadRoute(target);
}

async function loadRoute(route) {
  const request = ++routeRequest;
  try {
    if (route === "dashboard") await loadDashboard();
    if (route === "licenses") await loadLicenses();
    if (route === "requests") await loadRequests();
    if (route === "machines") await loadMachines();
    if (route === "products") await loadProductsPage();
    if (route === "issuers") await loadIssuers();
    if (route === "users") await loadUsers();
    if (route === "audit") await loadAudit(false);
  } catch (error) {
    if (request === routeRequest) toast(error.message || "Unable to load this page.", "error");
  }
}

async function ensureProducts(includeRetired = false) {
  let payload;
  if (isManagementReader()) {
    try {
      payload = await api(`${API}/admin/products?includeRetired=${includeRetired ? "true" : "false"}`);
    } catch (error) {
      if (error.status !== 404 && error.status !== 405) throw error;
    }
  }
  if (!payload) payload = await api(`${API}/products`);
  state.products = payload.items || [];
  populateProductSelects();
  return state.products;
}

function populateProductSelects() {
  const targets = [
    document.querySelector('#license-filters select[name="productCode"]'),
    document.querySelector('#machine-filters select[name="productCode"]'),
    document.querySelector('#request-filters select[name="productCode"]'),
  ];
  for (const select of targets) {
    if (!select) continue;
    const previous = select.value;
    const first = make("option", { value: "", text: "All products" });
    select.replaceChildren(first);
    for (const product of state.products.filter((item) => item.status === "active")) {
      select.append(make("option", { value: product.code, text: `${product.name} (${product.code})` }));
    }
    select.value = previous;
  }
  const issueSelect = document.querySelector('#license-form select[name="productCode"]');
  if (issueSelect) {
    const previous = issueSelect.value;
    issueSelect.replaceChildren();
    for (const product of state.products.filter((item) => item.status === "active")) {
      issueSelect.append(make("option", { value: product.code, text: `${product.name} (${product.code})` }));
    }
    if (previous) issueSelect.value = previous;
  }
  const requestSelect = document.querySelector('#license-request-form select[name="productCode"]');
  if (requestSelect) {
    const previous = requestSelect.value;
    requestSelect.replaceChildren();
    for (const product of state.products.filter((item) => item.status === "active")) {
      requestSelect.append(make("option", { value: product.code, text: `${product.name} (${product.code})` }));
    }
    if (previous) requestSelect.value = previous;
  }
}

function metricCard(label, value, note) {
  const card = make("article", { className: "metric-card" });
  append(
    card,
    make("span", { className: "metric-label", text: label }),
    make("strong", { text: Number(value || 0).toLocaleString() }),
    make("small", { text: note }),
  );
  return card;
}

function firstNumber(source, keys, fallback = 0) {
  for (const key of keys) {
    if (Number.isFinite(Number(source?.[key]))) return Number(source[key]);
  }
  return fallback;
}

async function loadDashboard() {
  const metrics = byId("metric-grid");
  const breakdown = byId("state-breakdown");
  const recent = byId("recent-licenses");
  const expiring = byId("expiring-list");
  setError(byId("dashboard-error"), null);
  loading(metrics, "Loading overview…");
  loading(recent, "Loading recent licenses…");
  try {
    await ensureProducts(false);
    let dashboard = null;
    if (isManagementReader()) {
      try {
        dashboard = await api(`${API}/admin/dashboard`);
      } catch (error) {
        if (error.status !== 404 && error.status !== 405) throw error;
      }
    }
    let licenses = dashboard?.recentLicenses || dashboard?.licenses || [];
    if (!Array.isArray(licenses) || licenses.length === 0) {
      const payload = await api(isManagementReader() ? `${API}/admin/licenses?limit=200` : `${API}/licenses`);
      licenses = payload.items || [];
    }
    const summary = dashboard?.summary || dashboard?.metrics || dashboard || {};
    let customerActivations = [];
    if (!isManagementReader() && licenses.length) {
      const results = await Promise.allSettled(
        licenses.map((license) => api(`${API}/licenses/${encodeURIComponent(license.id)}/activations`)),
      );
      customerActivations = results.flatMap((result) => result.status === "fulfilled" ? result.value.items || [] : []);
    }
    const total = firstNumber(summary, ["totalLicenses", "licensesTotal"], licenses.length);
    const active = firstNumber(
      summary,
      ["activeLicenses", "licensesActive"],
      licenses.filter((item) => item.state === "active").length,
    );
    const machines = firstNumber(
      summary,
      ["activeActivations", "activeMachines", "machinesActive"],
      customerActivations.filter((item) => item.state === "active").length,
    );
    const allocated = firstNumber(
      summary,
      ["claimedLicenses", "assignedLicenses"],
      licenses.filter((item) => item.ownerUserId || item.ownerEmail).length,
    );
    metrics.replaceChildren(
      metricCard("Total licenses", total, `${active.toLocaleString()} currently active`),
      metricCard("Active machines", machines, "Current machine activations"),
      metricCard("Assigned", allocated, "Licenses claimed by an owner"),
      metricCard("Products", firstNumber(summary, ["totalProducts", "productsTotal"], state.products.length), "Active catalog entries"),
    );
    renderBreakdown(breakdown, summary, licenses, total);
    renderExpiring(expiring, dashboard?.expiringLicenses || licenses);
    renderLicenseTable(recent, licenses.slice(0, 8), { compact: true });
  } catch (error) {
    setError(byId("dashboard-error"), error);
    empty(metrics, "Overview unavailable", "Refresh to try again.");
    empty(recent, "No data", "Recent licenses could not be loaded.");
    throw error;
  }
}

function renderBreakdown(container, summary, licenses, total) {
  container.replaceChildren();
  const values = [
    ["Active", firstNumber(summary, ["activeLicenses", "licensesActive"], licenses.filter((item) => item.state === "active").length)],
    ["Suspended", firstNumber(summary, ["suspendedLicenses", "licensesSuspended"], licenses.filter((item) => item.state === "suspended").length)],
    ["Revoked", firstNumber(summary, ["revokedLicenses", "licensesRevoked"], licenses.filter((item) => item.state === "revoked").length)],
  ];
  for (const [label, value] of values) {
    const row = make("div", { className: "breakdown-row" });
    const track = make("progress", {
      className: "bar-track",
      value,
      attributes: { max: String(Math.max(total, 1)), "aria-label": `${label}: ${value} of ${total}` },
    });
    append(row, make("span", { text: label }), track, make("strong", { text: value }));
    container.append(row);
  }
}

function renderExpiring(container, input) {
  const now = Date.now();
  const horizon = now + 30 * 86400000;
  const items = input
    .filter((item) => item.expiresAt && new Date(item.expiresAt).valueOf() >= now && new Date(item.expiresAt).valueOf() <= horizon)
    .sort((a, b) => new Date(a.expiresAt) - new Date(b.expiresAt))
    .slice(0, 5);
  if (!items.length) {
    empty(container, "Nothing expiring soon", "No visible licenses expire in the next 30 days.");
    return;
  }
  container.replaceChildren();
  for (const license of items) {
    const row = make("div", { className: "compact-item" });
    const label = make("div");
    append(label, make("strong", { text: license.ownerEmail || license.subject || license.serial }), make("small", { text: license.productCode }));
    append(row, label, make("small", { text: formatDate(license.expiresAt, false) }));
    container.append(row);
  }
}

function getLicenseQuery() {
  const params = new URLSearchParams();
  if (!isManagementReader()) return params;
  for (const field of byId("license-filters").elements) {
    if (!field.name || !field.value) continue;
    const value = String(field.value).trim();
    if (value) params.set(field.dataset.apiParam || field.name, value);
  }
  params.set("limit", "200");
  return params;
}

async function loadLicenses() {
  const request = ++listRequests.licenses;
  const container = byId("licenses-table");
  syncLifecycleTabs("license-filters");
  setError(byId("licenses-error"), null);
  loading(container, "Loading licenses…");
  const endpoint = isManagementReader()
    ? `${API}/admin/licenses?${getLicenseQuery().toString()}`
    : `${API}/licenses`;
  try {
    await ensureProducts(false);
    const payload = await api(endpoint);
    if (request !== listRequests.licenses) return;
    state.licenses = payload.items || [];
    byId("license-result-summary").textContent = `${state.licenses.length.toLocaleString()} license${state.licenses.length === 1 ? "" : "s"} shown`;
    renderLicenseTable(container, state.licenses);
  } catch (error) {
    if (request !== listRequests.licenses) return;
    setError(byId("licenses-error"), error);
    empty(container, "Licenses unavailable", "Adjust the filters or refresh to try again.");
    throw error;
  }
}

function getRequestQuery() {
  const params = new URLSearchParams({ limit: "200" });
  if (!isManagementReader()) return params;
  for (const field of byId("request-filters").elements) {
    if (!field.name || !field.value) continue;
    const value = String(field.value).trim();
    if (value) params.set(field.name, value);
  }
  return params;
}

async function loadRequests() {
  const request = ++listRequests.requests;
  const container = byId("requests-table");
  setError(byId("requests-error"), null);
  loading(container, "Loading license requests…");
  const endpoint = isManagementReader()
    ? `${API}/admin/license-requests?${getRequestQuery().toString()}`
    : `${API}/license-requests`;
  try {
    await ensureProducts(false);
    const payload = await api(endpoint);
    if (request !== listRequests.requests) return;
    state.requests = payload.items || [];
    byId("request-result-summary").textContent = `${state.requests.length.toLocaleString()} request${state.requests.length === 1 ? "" : "s"} shown`;
    renderRequestTable(container, state.requests);
  } catch (error) {
    if (request !== listRequests.requests) return;
    setError(byId("requests-error"), error);
    empty(container, "Requests unavailable", "Refresh or adjust the filters to try again.");
    throw error;
  }
}

function requestProductCode(request) {
  if (request.productCode) return request.productCode;
  return state.products.find((product) => String(product.id) === String(request.productId))?.code || "Unknown product";
}

function renderRequestTable(container, requests) {
  if (!requests.length) {
    empty(
      container,
      "No license requests",
      isCustomer() ? "Submit a request when you need access to a product." : "No customer request matches the current filters.",
    );
    return;
  }
  const admin = isManagementReader();
  const headers = admin
    ? ["Customer", "Product", "Seats", "Status", "Submitted", "License", ""]
    : ["Product", "Seats", "Status", "Submitted", "License", ""];
  const { element, body } = table(headers);
  for (const request of requests) {
    const row = make("tr");
    if (admin) row.append(primaryCell(request.requesterEmail || shortId(request.requesterUserId, 18)));
    append(
      row,
      primaryCell(requestProductCode(request), shortId(request.id, 18)),
      make("td", { text: Number(request.requestedActivations || 1).toLocaleString() }),
      cellWith(badge(request.status)),
      make("td", { text: formatDate(request.createdAt) }),
      primaryCell(request.fulfilledLicenseId ? shortId(request.fulfilledLicenseId, 18) : "—"),
    );
    const actions = make("td");
    actions.append(
      makeButton(admin && request.status === "pending" && isLicenseWriter() ? "Review" : "View", "button secondary", (event) =>
        openRequestDrawer(request.id, event.currentTarget),
      ),
    );
    row.append(actions);
    body.append(row);
  }
  container.replaceChildren(element);
}

async function openRequestDrawer(requestId, returnFocus = null) {
  openDrawer("License request", "Fulfillment", returnFocus);
  loading(byId("drawer-body"), "Loading request…");
  try {
    const prefix = isManagementReader() ? `${API}/admin` : API;
    const payload = await api(`${prefix}/license-requests/${encodeURIComponent(requestId)}`);
    renderRequestDetails(payload.request);
  } catch (error) {
    empty(byId("drawer-body"), "Request unavailable", error.message || "The request could not be loaded.");
  }
}

function formControlLabel(text, control, help = "") {
  const label = make("label", { text });
  label.append(control);
  if (help) label.append(make("small", { text: help }));
  return label;
}

function renderRequestDetails(request) {
  byId("drawer-title").textContent = requestProductCode(request);
  const record = detailSection("Request record");
  const grid = make("dl", { className: "detail-grid" });
  append(
    grid,
    detailField("Request ID", request.id, "mono"),
    detailField("Status", String(request.status || "unknown").replaceAll("_", " ")),
    detailField("Customer", request.requesterEmail || state.user?.email || request.requesterUserId),
    detailField("Product", requestProductCode(request)),
    detailField("Requested seats", request.requestedActivations),
    detailField("Submitted", formatDate(request.createdAt)),
    detailField("Reviewed", formatDate(request.reviewedAt)),
    detailField("Fulfilled license", request.fulfilledLicenseId || "—", "mono"),
  );
  record.append(grid);
  if (request.message) {
    append(record, make("h4", { text: "Customer message" }), make("p", { className: "preserve-text", text: request.message }));
  }
  if (request.adminNotes) {
    append(record, make("h4", { text: "Administrator notes" }), make("p", { className: "preserve-text", text: request.adminNotes }));
  }
  if (isCustomer() && request.status === "pending") {
    const actions = make("div", { className: "detail-actions" });
    actions.append(makeButton("Cancel request", "button danger-outline", () => cancelLicenseRequest(request)));
    record.append(actions);
  }

  const sections = [record];
  if (isLicenseWriter() && request.status === "pending") sections.push(renderRequestReview(request));
  byId("drawer-body").replaceChildren(...sections);
}

function renderRequestReview(request) {
  const review = detailSection("Review and fulfill");
  review.append(make("p", { className: "muted", text: "Approval creates a license assigned directly to this customer. Confirm every entitlement before issuing." }));
  const approveForm = make("form", { className: "stack-form request-review-form" });
  const approveError = make("div", { className: "alert error", attributes: { role: "alert" }, hidden: true });
  const product = make("div", { className: "request-product-summary" });
  append(product, make("span", { className: "field-label", text: "Product" }), make("strong", { text: requestProductCode(request) }));
  const subject = make("input", { name: "subject", attributes: { maxlength: "320", placeholder: request.requesterEmail || "Customer reference" } });
  subject.value = request.requesterEmail || "";
  const seats = make("input", { type: "number", name: "maxActivations", value: request.requestedActivations || 1, attributes: { min: "1", max: "100000", required: "" } });
  const grace = make("input", { type: "number", name: "offlineGraceHours", value: 24, attributes: { min: "1", max: "720", required: "" } });
  const validFrom = make("input", { type: "datetime-local", name: "notBefore" });
  const expires = make("input", { type: "datetime-local", name: "expiresAt" });
  const formGrid = make("div", { className: "form-grid" });
  append(
    formGrid,
    formControlLabel("Subject", subject),
    formControlLabel("Machine seats", seats),
    formControlLabel("Offline grace (hours)", grace),
    formControlLabel("Valid from", validFrom),
    formControlLabel("Expires at", expires),
  );
  const perpetual = make("input", { type: "checkbox", name: "perpetual" });
  const perpetualLabel = make("label", { className: "check-row", text: " Perpetual license (no expiration)" });
  perpetualLabel.prepend(perpetual);
  const entitlements = make("textarea", { name: "entitlements", attributes: { rows: "7", spellcheck: "false" } });
  entitlements.value = "{}";
  entitlements.placeholder = '{\n  "feature.analytics": true,\n  "limits.projects": 25\n}';
  const help = makeButton("How entitlements control software features", "text-button inline-action", () => byId("entitlements-guide-dialog").showModal());
  const approve = makeButton("Approve and issue license", "button primary");
  approve.type = "submit";
  append(
    approveForm,
    approveError,
    product,
    formGrid,
    perpetualLabel,
    formControlLabel("Entitlements (JSON object)", entitlements, "Use booleans for feature switches, integers for limits, and strings for tiers."),
    help,
    approve,
  );
  approveForm.addEventListener("submit", (event) => approveLicenseRequest(event, request, approveError));

  const denyForm = make("form", { className: "stack-form request-deny-form" });
  const denyError = make("div", { className: "alert error", attributes: { role: "alert" }, hidden: true });
  const notes = make("textarea", { name: "adminNotes", attributes: { rows: "4", maxlength: "2000", required: "", placeholder: "Explain why this request cannot be fulfilled." } });
  const deny = makeButton("Deny request", "button danger-outline");
  deny.type = "submit";
  append(denyForm, make("h4", { text: "Deny instead" }), denyError, formControlLabel("Administrator notes", notes, "The customer will see this explanation."), deny);
  denyForm.addEventListener("submit", (event) => denyLicenseRequest(event, request, denyError));
  append(review, approveForm, denyForm);
  return review;
}

async function approveLicenseRequest(event, request, errorElement) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  setError(errorElement, null);
  submit.disabled = true;
  try {
    let entitlements;
    try {
      entitlements = JSON.parse(String(data.get("entitlements") || "{}"));
      if (!entitlements || Array.isArray(entitlements) || typeof entitlements !== "object") throw new Error();
    } catch {
      throw new Error("Entitlements must be a valid JSON object.");
    }
    const perpetual = data.get("perpetual") === "on";
    const expiresAt = localDateToRFC3339(String(data.get("expiresAt") || ""));
    if (perpetual && expiresAt) throw new Error("A perpetual license cannot have an expiration date.");
    if (!perpetual && !expiresAt) throw new Error("Choose an expiration or mark the license perpetual.");
    const body = {
      subject: String(data.get("subject") || "").trim(),
      maxActivations: Number(data.get("maxActivations")),
      offlineGraceSeconds: Number(data.get("offlineGraceHours")) * 3600,
      perpetual,
      entitlements,
    };
    const notBefore = localDateToRFC3339(String(data.get("notBefore") || ""));
    if (notBefore) body.notBefore = notBefore;
    if (expiresAt) body.expiresAt = expiresAt;
    const confirmed = await confirmAction(
      "Approve and issue this license?",
      `A ${requestProductCode(request)} license with ${body.maxActivations} machine seat${body.maxActivations === 1 ? "" : "s"} will be assigned directly to ${request.requesterEmail || "the customer"}.`,
      "Approve and issue",
    );
    if (!confirmed) return;
    const payload = await api(`${API}/admin/license-requests/${encodeURIComponent(request.id)}/approve`, { method: "POST", body });
    toast(payload.idempotent ? "The existing fulfilled license was recovered." : "Request approved and license assigned.");
    renderRequestDetails(payload.request);
    loadRequests();
  } catch (error) {
    setError(errorElement, error);
  } finally {
    submit.disabled = false;
  }
}

async function denyLicenseRequest(event, request, errorElement) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const adminNotes = String(new FormData(form).get("adminNotes") || "").trim();
  setError(errorElement, null);
  const confirmed = await confirmAction(
    "Deny this license request?",
    `The request from ${request.requesterEmail || "this customer"} will be closed with the explanation you entered.`,
    "Deny request",
  );
  if (!confirmed) return;
  submit.disabled = true;
  try {
    const payload = await api(`${API}/admin/license-requests/${encodeURIComponent(request.id)}/deny`, { method: "POST", body: { adminNotes } });
    toast("License request denied.");
    renderRequestDetails(payload.request);
    loadRequests();
  } catch (error) {
    setError(errorElement, error);
  } finally {
    submit.disabled = false;
  }
}

async function cancelLicenseRequest(request) {
  const confirmed = await confirmAction(
    "Cancel this request?",
    "The pending request will be closed. You can submit a new request for this product later.",
    "Cancel request",
  );
  if (!confirmed) return;
  try {
    const payload = await api(`${API}/license-requests/${encodeURIComponent(request.id)}/cancel`, { method: "POST" });
    toast("License request cancelled.");
    renderRequestDetails(payload.request);
    loadRequests();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function openLicenseRequestDialog() {
  try {
    await ensureProducts(false);
    if (!state.products.some((product) => product.status === "active")) {
      toast("No products are currently available for requests.", "error");
      return;
    }
    const form = byId("license-request-form");
    form.reset();
    populateProductSelects();
    setError(byId("license-request-form-error"), null);
    byId("license-request-dialog").showModal();
    window.setTimeout(() => form.elements.productCode.focus(), 0);
  } catch (error) {
    toast(error.message, "error");
  }
}

async function createLicenseRequest(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  setError(byId("license-request-form-error"), null);
  submit.disabled = true;
  try {
    await api(`${API}/license-requests`, {
      method: "POST",
      body: {
        productCode: String(data.get("productCode") || ""),
        requestedActivations: Number(data.get("requestedActivations")),
        message: String(data.get("message") || "").trim(),
      },
    });
    byId("license-request-dialog").close();
    form.reset();
    toast("License request submitted.");
    loadRequests();
  } catch (error) {
    setError(byId("license-request-form-error"), error);
  } finally {
    submit.disabled = false;
  }
}

function openClaimLicenseDialog() {
  const form = byId("claim-license-form");
  form.reset();
  setError(byId("claim-license-error"), null);
  byId("claim-license-dialog").showModal();
  window.setTimeout(() => form.elements.claimCode.focus(), 0);
}

async function claimLicense(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const claimCode = String(new FormData(form).get("claimCode") || "").trim();
  setError(byId("claim-license-error"), null);
  submit.disabled = true;
  try {
    await api(`${API}/licenses/claim`, { method: "POST", body: { claimCode } });
    byId("claim-license-dialog").close();
    form.reset();
    toast("License claimed and added to your account.");
    loadLicenses();
  } catch (error) {
    setError(byId("claim-license-error"), error);
  } finally {
    submit.disabled = false;
  }
}

function table(headers) {
  const element = make("table");
  const head = make("thead");
  const row = make("tr");
  for (const header of headers) row.append(make("th", { text: header, attributes: { scope: "col" } }));
  head.append(row);
  const body = make("tbody");
  append(element, head, body);
  return { element, body };
}

function primaryCell(primary, secondary = "") {
  const cell = make("td");
  append(cell, make("span", { className: "cell-primary", text: primary }), secondary ? make("span", { className: "cell-secondary", text: secondary }) : null);
  return cell;
}

function recordLifecycle(record) {
  if (record?.deletedAt) return "deleted";
  if (record?.archivedAt) return "archived";
  return "current";
}

function licenseStateTransitions(currentState) {
  return {
    active: ["suspended", "revoked"],
    suspended: ["active", "revoked"],
    revoked: [],
  }[currentState] || [];
}

function syncLifecycleTabs(formId) {
  const form = byId(formId);
  const value = form?.elements?.lifecycle?.value || "current";
  for (const button of document.querySelectorAll(`[data-lifecycle-form="${formId}"]`)) {
    const active = button.dataset.lifecycleValue === value;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  }
}

function selectLifecycle(button) {
  const formId = button.dataset.lifecycleForm;
  const form = byId(formId);
  if (!form?.elements?.lifecycle) return;
  form.elements.lifecycle.value = button.dataset.lifecycleValue;
  syncLifecycleTabs(formId);
  if (formId === "license-filters") loadLicenses();
  if (formId === "user-search") loadUsers();
}

function renderLicenseTable(container, licenses, options = {}) {
  if (!licenses.length) {
    empty(container, "No licenses found", "No license matches the current view or filters.");
    return;
  }
  const headers = options.compact
    ? ["Serial", "Product", "Owner", "State", "Expires", ""]
    : ["License", "Product", "Owner", "Source", "Seats", "State", "Lifecycle", "Expires", ""];
  const { element, body } = table(headers);
  for (const license of licenses) {
    const row = make("tr");
    if (options.compact) {
      append(
        row,
        primaryCell(shortId(license.serial, 16), license.claimCodeSuffix ? `Claim •••• ${license.claimCodeSuffix}` : ""),
        primaryCell(license.productCode),
        primaryCell(license.ownerEmail || "Unassigned"),
        cellWith(badge(license.state)),
        make("td", { text: license.expiresAt ? formatDate(license.expiresAt, false) : "Perpetual" }),
      );
    } else {
      append(
        row,
        primaryCell(shortId(license.serial, 18), license.subject || `Claim •••• ${license.claimCodeSuffix || "—"}`),
        primaryCell(license.productCode),
        primaryCell(license.ownerEmail || "Unassigned", license.claimedAt ? `Claimed ${formatDate(license.claimedAt, false)}` : "Not claimed"),
        make("td", { text: String(license.source || "").replaceAll("_", " ") }),
        make("td", { text: license.maxActivations }),
        cellWith(badge(license.state)),
        cellWith(badge(recordLifecycle(license))),
        make("td", { text: license.expiresAt ? formatDate(license.expiresAt, false) : "Perpetual" }),
      );
    }
    const actionCell = make("td");
    const actions = make("div", { className: "table-actions" });
    actions.append(
      makeButton(isLicenseWriter() ? "Manage" : "View", "button secondary", (event) =>
        openLicenseDrawer(license.id, event.currentTarget),
      ),
    );
    if (!options.compact && isLicenseWriter() && !license.deletedAt) {
      if (!license.archivedAt) {
        actions.append(makeButton("Archive", "button danger-outline", () => changeLicenseLifecycle(license, "archive")));
      } else {
        actions.append(makeButton("Restore", "button secondary", () => changeLicenseLifecycle(license, "restore")));
        if (hasRole("platform_owner") && license.state === "revoked") {
          actions.append(makeButton("Delete", "button danger", () => changeLicenseLifecycle(license, "delete")));
        }
      }
    }
    actionCell.append(actions);
    row.append(actionCell);
    body.append(row);
  }
  container.replaceChildren(element);
}

function cellWith(child) {
  const cell = make("td");
  cell.append(child);
  return cell;
}

async function openLicenseDrawer(licenseId, returnFocus = null) {
  openDrawer("License details", "Inventory", returnFocus);
  loading(byId("drawer-body"), "Loading license and machines…");
  try {
    const prefix = isManagementReader() ? `${API}/admin` : API;
    const [licensePayload, activationPayload] = await Promise.all([
      api(`${prefix}/licenses/${encodeURIComponent(licenseId)}`),
      api(`${prefix}/licenses/${encodeURIComponent(licenseId)}/activations`),
    ]);
    renderLicenseDetails(licensePayload.license, activationPayload.items || []);
  } catch (error) {
    const body = byId("drawer-body");
    empty(body, "License unavailable", error.message || "The details could not be loaded.");
  }
}

function openDrawer(title, kicker, returnFocus) {
  const drawer = byId("detail-drawer");
  if (!drawer.classList.contains("open")) {
    state.drawerReturnFocus = returnFocus || document.activeElement;
  }
  byId("drawer-title").textContent = title;
  byId("drawer-kicker").textContent = kicker;
  byId("drawer-backdrop").hidden = false;
  byId("app-shell").setAttribute("inert", "");
  drawer.classList.add("open");
  drawer.removeAttribute("inert");
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
  window.setTimeout(() => byId("drawer-close").focus(), 0);
}

function closeDrawer() {
  const drawer = byId("detail-drawer");
  if (!drawer.classList.contains("open")) return;
  drawer.classList.remove("open");
  drawer.setAttribute("inert", "");
  drawer.setAttribute("aria-hidden", "true");
  byId("drawer-backdrop").hidden = true;
  byId("app-shell").removeAttribute("inert");
  document.body.classList.remove("drawer-open");
  const focus = state.drawerReturnFocus;
  state.drawerReturnFocus = null;
  if (focus?.isConnected) focus.focus();
}

function detailField(label, value, className = "") {
  const wrapper = make("div", { className: `detail-field ${className}`.trim() });
  append(wrapper, make("dt", { text: label }), make("dd", { text: value ?? "—" }));
  return wrapper;
}

function detailSection(title) {
  const section = make("section", { className: "detail-section" });
  section.append(make("h3", { text: title }));
  return section;
}

function renderLicenseDetails(license, activations) {
  byId("drawer-title").textContent = license.productCode || "License";
  const body = byId("drawer-body");
  const overview = detailSection("License record");
  const overviewGrid = make("dl", { className: "detail-grid" });
  append(
    overviewGrid,
    detailField("Serial", license.serial, "mono"),
    detailField("State", String(license.state).replaceAll("_", " ")),
    detailField("Owner", license.ownerEmail || "Unassigned"),
    detailField("Subject", license.subject || "—"),
    detailField("Source", String(license.source || "").replaceAll("_", " ")),
    detailField("Claim suffix", license.claimCodeSuffix ? `•••• ${license.claimCodeSuffix}` : "—"),
    detailField("Issued", formatDate(license.issuedAt)),
    detailField("Valid from", formatDate(license.notBefore)),
    detailField("Expires", license.expiresAt ? formatDate(license.expiresAt) : "Perpetual"),
    detailField("Offline grace", formatDuration(license.offlineGraceSeconds)),
    detailField("Machine seats", license.maxActivations),
    detailField("Revision", license.revision),
    detailField("Archived", formatDate(license.archivedAt)),
    detailField("Deleted", formatDate(license.deletedAt)),
  );
  overview.append(overviewGrid);
  if (isLicenseWriter() && !license.archivedAt && !license.deletedAt) {
    const nextStates = licenseStateTransitions(license.state);
    const actions = make("div", { className: "detail-actions" });
    for (const nextState of nextStates) {
      const label = nextState === "active" ? "Restore active" : `${nextState[0].toUpperCase()}${nextState.slice(1)}`;
      actions.append(
        makeButton(label, nextState === "revoked" ? "button danger-outline" : "button secondary", () => changeLicenseState(license, nextState)),
      );
    }
    if (license.state === "revoked") {
      actions.append(make("p", {
        className: "lifecycle-guidance",
        text: "Revocation is permanent. This license cannot be returned to active or suspended state.",
      }));
    }
    overview.append(actions);
  }
  let lifecycleSection = null;
  if (isLicenseWriter() && !license.deletedAt) {
    lifecycleSection = detailSection("Lifecycle management");
    lifecycleSection.append(make("p", {
      className: "lifecycle-policy",
      text: "Archive is reversible and stops operational use. Permanent deletion is restricted to platform owners and requires the license to be revoked and archived first.",
    }));
    const lifecycle = make("div", { className: "detail-actions" });
    if (!license.archivedAt) {
      lifecycle.append(makeButton("Archive license", "button danger-outline", () => changeLicenseLifecycle(license, "archive")));
      if (hasRole("platform_owner") && license.state !== "revoked") {
        lifecycle.append(make("p", {
          className: "lifecycle-guidance",
          text: "To permanently delete this record later, revoke the license before archiving it.",
        }));
      }
    } else {
      lifecycle.append(makeButton("Restore from archive", "button secondary", () => changeLicenseLifecycle(license, "restore")));
      if (hasRole("platform_owner") && license.state === "revoked") {
        lifecycle.append(makeButton("Permanently delete", "button danger", () => changeLicenseLifecycle(license, "delete")));
      } else if (hasRole("platform_owner")) {
        lifecycle.append(make("p", {
          className: "lifecycle-guidance",
          text: "Permanent deletion requires a revoked archive. Restore this record, revoke the license, then archive it again before deleting it.",
        }));
      }
    }
    lifecycleSection.append(lifecycle);
  }

  const entitlements = detailSection("Entitlements");
  const entries = Object.entries(license.entitlements || {});
  if (!entries.length) {
    entitlements.append(make("p", { className: "muted", text: "No entitlements are attached to this license." }));
  } else {
    const list = make("div", { className: "entitlement-list" });
    for (const [key, value] of entries) {
      const item = make("div", { className: "entitlement" });
      append(item, make("strong", { text: key }), make("span", { text: String(value) }));
      list.append(item);
    }
    entitlements.append(list);
  }
  entitlements.append(
    makeButton("Read the entitlement integration guide", "text-button inline-action", () =>
      byId("entitlements-guide-dialog").showModal(),
    ),
  );

  const activeMachines = activations.filter((item) => item.state === "active").length;
  const machines = detailSection(
    `Machines (${activeMachines}/${license.maxActivations} active · ${activations.length} total records)`,
  );
  if (!activations.length) {
    machines.append(make("p", { className: "muted", text: "This license has not been activated on a machine." }));
  } else {
    for (const activation of activations) machines.append(renderMachineCard(activation, license));
  }
  body.replaceChildren(...[overview, lifecycleSection, entitlements, machines].filter(Boolean));
}

function machineFingerprint(activation) {
  return activation.deviceKeyThumbprint || activation.deviceFingerprint || activation.devicePublicKey || activation.id;
}

function renderMachineCard(activation, license = null) {
  const card = make("article", { className: "machine-card" });
  const head = make("div", { className: "machine-head" });
  const title = make("div");
  append(title, make("h4", { text: activation.label || "Unnamed machine" }), make("span", { className: "mono muted", text: shortId(machineFingerprint(activation), 25), title: machineFingerprint(activation) }));
  append(head, title, badge(activation.state));
  const meta = make("div", { className: "machine-meta" });
  for (const [name, value] of [
    ["Activated", formatDate(activation.activatedAt)],
    ["Last seen", formatDate(activation.lastSeenAt)],
    ["Lease expires", formatDate(activation.leaseExpiresAt)],
    ["Deactivated", formatDate(activation.deactivatedAt)],
  ]) {
    const item = make("div");
    append(item, make("span", { text: name }), make("strong", { text: value }));
    meta.append(item);
  }
  append(card, head, meta);
  if (canDeactivate() && activation.state === "active") {
    card.append(makeButton("Deactivate machine", "button danger-outline", () => deactivateMachine(activation, license)));
  }
  return card;
}

async function changeLicenseState(license, nextState) {
  if (!licenseStateTransitions(license.state).includes(nextState)) {
    toast("That license state transition is not permitted.", "error");
    return;
  }
  const destructive = nextState === "revoked";
  const confirmed = await confirmAction(
    `${nextState[0].toUpperCase()}${nextState.slice(1)} license?`,
    destructive
      ? "Revoking prevents this license from being used. Existing activation leases will stop renewing."
      : `The license will be changed from ${license.state} to ${nextState}.`,
    destructive ? "Revoke license" : "Change state",
  );
  if (!confirmed) return;
  try {
    await api(`${API}/admin/licenses/${encodeURIComponent(license.id)}/state`, {
      method: "POST",
      body: { state: nextState },
    });
    toast(`License changed to ${nextState}.`);
    await openLicenseDrawer(license.id);
    if (state.route === "licenses") loadLicenses();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function changeLicenseLifecycle(license, action) {
  let confirmed;
  if (action === "archive") {
    confirmed = await confirmAction(
      "Archive this license?",
      "The license will be hidden from current inventory. Active licenses are suspended; revoked licenses remain revoked. Existing activation leases will stop renewing.",
      "Archive license",
    );
  } else if (action === "restore") {
    confirmed = await confirmAction(
      "Restore this license record?",
      "The license will return to current inventory but remain in its suspended or revoked state. Restore never reactivates a license.",
      "Restore record",
    );
  } else {
    confirmed = await confirmAction(
      "Permanently delete this license?",
      "Deletion tombstones this revoked, archived license so it cannot be restored or used. Audit and historical references are retained. Type the complete serial to continue.",
      "Permanently delete",
      license.serial,
    );
  }
  if (!confirmed) return;
  const body = { expectedRevision: license.revision };
  if (action === "delete") body.serial = license.serial;
  try {
    const payload = await api(`${API}/admin/licenses/${encodeURIComponent(license.id)}/${action}`, { method: "POST", body });
    if (action === "delete") {
      toast("License permanently deleted. Open Deleted above to view its retained tombstone.");
      closeDrawer();
    } else {
      const resultingState = payload?.license?.state || license.state;
      toast(action === "archive"
        ? `License archived in ${resultingState} state. Open Archived above to find it.`
        : `License restored in ${resultingState} state. Open Current above to find it.`);
      await openLicenseDrawer(payload?.license?.id || license.id);
    }
    if (state.route === "licenses") loadLicenses();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function deactivateMachine(activation, license = null) {
  const confirmed = await confirmAction(
    "Deactivate this machine?",
    `${activation.label || "This machine"} will lose its activation. The license seat will become available.`,
    "Deactivate machine",
  );
  if (!confirmed) return;
  try {
    const endpoint = isCustomer()
      ? `${API}/activations/${encodeURIComponent(activation.id)}`
      : `${API}/admin/activations/${encodeURIComponent(activation.id)}`;
    await api(endpoint, { method: "DELETE" });
    toast("Machine deactivated and seat released.");
    if (license?.id) await openLicenseDrawer(license.id);
    if (state.route === "machines") loadMachines();
  } catch (error) {
    toast(error.message, "error");
  }
}

function getMachineQuery() {
  const params = new URLSearchParams();
  for (const field of byId("machine-filters").elements) {
    if (!field.name || !field.value) continue;
    const value = String(field.value).trim();
    if (value) params.set(field.dataset.apiParam || field.name, value);
  }
  params.set("limit", "200");
  return params;
}

async function loadMachines() {
  const request = ++listRequests.machines;
  const container = byId("machines-table");
  setError(byId("machines-error"), null);
  loading(container, "Loading machine installations…");
  const endpoint = `${API}/admin/activations?${getMachineQuery().toString()}`;
  try {
    await ensureProducts(false);
    const payload = await api(endpoint);
    if (request !== listRequests.machines) return;
    state.machines = payload.items || [];
    byId("machine-result-summary").textContent = `${state.machines.length.toLocaleString()} installation${state.machines.length === 1 ? "" : "s"} shown`;
    renderMachinesTable(container, state.machines);
  } catch (error) {
    if (request !== listRequests.machines) return;
    setError(byId("machines-error"), error);
    empty(container, "Machines unavailable", "Adjust the filters or refresh to try again.");
    throw error;
  }
}

function normalizeMachine(item) {
  const activation = item.activation || item;
  return {
    ...activation,
    licenseId: activation.licenseId || item.licenseId || item.license?.id,
    licenseSerial: item.licenseSerial || item.serial || item.license?.serial || "",
    productCode: item.productCode || item.license?.productCode || "",
    ownerEmail: item.ownerEmail || item.license?.ownerEmail || "",
  };
}

function renderMachinesTable(container, machines) {
  if (!machines.length) {
    empty(container, "No machines found", "No installation matches the current filters.");
    return;
  }
  const { element, body } = table(["Machine", "Device key", "License", "Product", "Owner", "Last seen", "Lease", "State", ""]);
  for (const item of machines) {
    const machine = normalizeMachine(item);
    const row = make("tr");
    append(
      row,
      primaryCell(machine.label || "Unnamed machine", shortId(machine.id, 18)),
      primaryCell(shortId(machineFingerprint(machine), 18)),
      primaryCell(shortId(machine.licenseSerial, 18)),
      make("td", { text: machine.productCode || "—" }),
      primaryCell(machine.ownerEmail || "Unassigned"),
      make("td", { text: formatDate(machine.lastSeenAt) }),
      make("td", { text: formatDate(machine.leaseExpiresAt) }),
      cellWith(badge(machine.state)),
    );
    const actions = make("td");
    if (machine.licenseId) actions.append(makeButton("License", "button secondary", (event) => openLicenseDrawer(machine.licenseId, event.currentTarget)));
    row.append(actions);
    body.append(row);
  }
  container.replaceChildren(element);
}

async function loadProductsPage() {
  const request = ++listRequests.products;
  const container = byId("products-table");
  setError(byId("products-error"), null);
  loading(container, "Loading products…");
  try {
    const products = await ensureProducts(true);
    if (request !== listRequests.products) return;
    renderProducts(container, products);
  } catch (error) {
    if (request !== listRequests.products) return;
    setError(byId("products-error"), error);
    empty(container, "Products unavailable", "Refresh to try again.");
    throw error;
  }
}

function renderProducts(container, products) {
  if (!products.length) {
    empty(
      container,
      "No products yet",
      isLicenseWriter() ? "Create a product before issuing licenses." : "No products are available to review.",
    );
    return;
  }
  const headers = ["Product", "Code", "Description", "Status", "Revision", "Created"];
  if (isLicenseWriter()) headers.push("");
  const { element, body } = table(headers);
  for (const product of products) {
    const row = make("tr");
    append(
      row,
      primaryCell(product.name),
      make("td", { className: "mono", text: product.code }),
      primaryCell(product.description || "—"),
      cellWith(badge(product.status)),
      make("td", { text: product.revision ?? "—" }),
      make("td", { text: formatDate(product.createdAt, false) }),
    );
    if (isLicenseWriter()) {
      const actions = make("td");
      if (["active", "retired"].includes(product.status)) {
        const nextStatus = product.status === "active" ? "retired" : "active";
        const label = nextStatus === "retired" ? "Retire" : "Reactivate";
        const button = makeButton(
          label,
          nextStatus === "retired" ? "button danger-outline" : "button secondary",
          () => changeProductStatus(product, nextStatus),
        );
        button.setAttribute("aria-label", `${label} ${product.name || product.code}`);
        actions.append(button);
      }
      row.append(actions);
    }
    body.append(row);
  }
  container.replaceChildren(element);
}

async function changeProductStatus(product, status) {
  const expectedRevision = Number(product.revision);
  if (!Number.isInteger(expectedRevision) || expectedRevision < 1) {
    toast("Refresh the product list before changing this product.", "error");
    return;
  }
  const retiring = status === "retired";
  const confirmed = await confirmAction(
    retiring ? "Retire this product?" : "Reactivate this product?",
    retiring
      ? `${product.name || product.code} will no longer be offered for new licenses or customer requests. Existing licenses remain intact.`
      : `${product.name || product.code} will become available for new licenses and customer requests.`,
    retiring ? "Retire product" : "Reactivate product",
  );
  if (!confirmed) return;
  try {
    await api(`${API}/admin/products/${encodeURIComponent(product.code)}/status`, {
      method: "POST",
      body: { status, expectedRevision },
    });
    toast(retiring ? "Product retired." : "Product reactivated.");
    await loadProductsPage();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function loadIssuers() {
  const request = ++listRequests.issuers;
  const result = byId("issuer-result");
  try {
    const payload = await api(`${API}/admin/issuers?limit=200`);
    if (request !== listRequests.issuers) return;
    state.issuers = payload.items || [];
    renderIssuerResult(result, state.issuers);
    const selectedKeyId = byId("issuer-status-form").elements.keyId.value.trim();
    configureIssuerStatusForm(state.issuers.find((item) => item.keyId === selectedKeyId) || null);
  } catch (error) {
    if (request !== listRequests.issuers) return;
    if (error.status === 404 || error.status === 405) {
      result.hidden = false;
      result.textContent = "Registered keys can be managed by key ID. Issuer inventory is unavailable on this server version.";
      return;
    }
    toast(error.message, "error");
  }
}

function configureIssuerStatusForm(issuer) {
  const form = byId("issuer-status-form");
  const status = form.elements.status;
  const submit = form.querySelector('button[type="submit"]');
  const guidance = byId("issuer-status-guidance");
  if (issuer) status.value = issuer.status;
  const revoked = issuer?.status === "revoked";
  status.disabled = revoked;
  submit.disabled = revoked;
  guidance.hidden = !revoked;
  guidance.textContent = revoked
    ? "This key is permanently revoked. It cannot be returned to active or retired status."
    : "";
}

function renderIssuerResult(container, issuers) {
  container.hidden = false;
  container.replaceChildren();
  if (!issuers.length) {
    container.textContent = "No offline issuer keys are registered yet.";
    return;
  }
  container.className = "issuer-list";
  for (const issuer of issuers) {
    const card = make("div", { className: "machine-card" });
    const head = make("div", { className: "machine-head" });
    const title = make("div");
    append(title, make("h4", { text: issuer.issuer }), make("span", { className: "mono muted", text: shortId(issuer.keyId, 28), title: issuer.keyId }));
    append(head, title, badge(issuer.status));
    const dates = make("p", { className: "muted", text: `Valid ${formatDate(issuer.notBefore)} to ${issuer.notAfter ? formatDate(issuer.notAfter) : "no fixed end"}` });
    const manage = makeButton("Manage key", "button secondary", () => {
      const form = byId("issuer-status-form");
      form.elements.keyId.value = issuer.keyId;
      configureIssuerStatusForm(issuer);
      (issuer.status === "revoked" ? form.elements.keyId : form.elements.status).focus();
    });
    append(card, head, dates, manage);
    container.append(card);
  }
}

async function loadUsers() {
  const request = ++listRequests.users;
  const container = byId("users-table");
  syncLifecycleTabs("user-search");
  setError(byId("users-error"), null);
  loading(container, "Loading users…");
  const data = new FormData(byId("user-search"));
  const email = String(data.get("userEmailSearch") || "").trim();
  const lifecycle = String(data.get("lifecycle") || "current");
  const params = new URLSearchParams({ limit: "200" });
  if (email) params.set("email", email);
  params.set("lifecycle", lifecycle);
  try {
    const payload = await api(`${API}/admin/users?${params.toString()}`);
    if (request !== listRequests.users) return;
    renderUsers(container, payload.items || []);
  } catch (error) {
    if (request !== listRequests.users) return;
    setError(byId("users-error"), error);
    empty(container, "Users unavailable", "Adjust the search or refresh to try again.");
    throw error;
  }
}

function renderUsers(container, users) {
  if (!users.length) {
    empty(container, "No users found", "No account matches that email.");
    return;
  }
  const { element, body } = table(["User", "Role", "Setup", "Verification", "Status", "Lifecycle", "Created", ""]);
  for (const user of users) {
    const row = make("tr");
    append(
      row,
      primaryCell(user.email, shortId(user.id, 18)),
      cellWith(badge(roleProfile(user.role).label)),
      make("td", { text: user.passwordSetupRequired ? "Pending" : "Complete" }),
      make("td", { text: user.emailVerifiedAt ? formatDate(user.emailVerifiedAt) : "Not verified" }),
      cellWith(badge(user.status)),
      cellWith(badge(recordLifecycle(user))),
      make("td", { text: formatDate(user.createdAt, false) }),
    );
    const actionCell = make("td");
    const actions = make("div", { className: "table-actions" });
    const isCurrentUser = String(user.id) === String(state.user?.id);
    actions.append(makeButton("Manage", "button secondary", (event) => openUserDrawer(user.id, event.currentTarget)));
    if (!isCurrentUser && !user.deletedAt) {
      if (user.passwordSetupRequired && !user.archivedAt && user.status === "active") {
        actions.append(makeButton("Resend invite", "button secondary", () => resendUserInvitation(user)));
      }
      if (!user.archivedAt) {
        actions.append(makeButton("Archive", "button danger-outline", () => changeUserLifecycle(user, "archive")));
      } else {
        actions.append(
          makeButton("Restore", "button secondary", () => changeUserLifecycle(user, "restore")),
          makeButton("Delete", "button danger", () => changeUserLifecycle(user, "delete")),
        );
      }
    }
    actionCell.append(actions);
    row.append(actionCell);
    body.append(row);
  }
  container.replaceChildren(element);
}

async function openUserDrawer(userId, returnFocus) {
  openDrawer("User details", "Access control", returnFocus);
  loading(byId("drawer-body"), "Loading account…");
  try {
    const payload = await api(`${API}/admin/users/${encodeURIComponent(userId)}`);
    renderUserDetails(payload.user);
  } catch (error) {
    empty(byId("drawer-body"), "User unavailable", error.message);
  }
}

function renderUserDetails(user) {
  byId("drawer-title").textContent = user.email;
  const isCurrentUser = String(user.id) === String(state.user?.id);
  const record = detailSection("Account record");
  const grid = make("dl", { className: "detail-grid" });
  append(
    grid,
    detailField("User ID", user.id, "mono"),
    detailField("Status", user.status),
    detailField("Role", roleProfile(user.role).label),
    detailField("Password setup", user.passwordSetupRequired ? "Pending invitation" : "Complete"),
    detailField("Email verified", user.emailVerifiedAt ? formatDate(user.emailVerifiedAt) : "Not verified"),
    detailField("Created", formatDate(user.createdAt)),
    detailField("Revision", user.revision),
    detailField("Archived", formatDate(user.archivedAt)),
    detailField("Deleted", formatDate(user.deletedAt)),
  );
  record.append(grid);

  let lifecycleSection = null;
  if (!user.deletedAt) {
    lifecycleSection = detailSection("Lifecycle management");
    lifecycleSection.append(make("p", {
      className: "lifecycle-policy",
      text: "Archive is reversible, disables the account, and signs it out everywhere. Permanent deletion anonymizes an archived account and cannot be undone.",
    }));
    const accountActions = make("div", { className: "detail-actions" });
    if (isCurrentUser) {
      accountActions.append(make("p", {
        className: "lifecycle-guidance",
        text: "You cannot archive or delete the account you are currently using. Sign in as a different platform owner to manage it.",
      }));
    } else {
      if (user.passwordSetupRequired && !user.archivedAt && user.status === "active") {
        accountActions.append(makeButton("Resend invitation", "button secondary", () => resendUserInvitation(user)));
      } else if (user.passwordSetupRequired && !user.archivedAt) {
        accountActions.append(make("p", {
          className: "lifecycle-guidance",
          text: "Enable this account before resending its pending password-setup invitation.",
        }));
      }
      if (!user.archivedAt) {
        accountActions.append(makeButton("Archive user", "button danger-outline", () => changeUserLifecycle(user, "archive")));
      } else {
        accountActions.append(
          makeButton("Restore from archive", "button secondary", () => changeUserLifecycle(user, "restore")),
          makeButton("Permanently delete", "button danger", () => changeUserLifecycle(user, "delete")),
        );
      }
    }
    lifecycleSection.append(accountActions);
  }

  const access = detailSection("Access management");
  const form = make("form", { className: "stack-form" });
  const formError = make("div", { className: "alert error", attributes: { role: "alert" }, hidden: true });
  const roleLabel = make("label", { text: "Role" });
  const roleSelect = make("select", { name: "role" });
  populateRoleSelect(roleSelect, user.role);
  roleLabel.append(roleSelect);
  const statusLabel = make("label", { text: "Status" });
  const statusSelect = make("select", { name: "status" });
  statusSelect.append(make("option", { value: "active", text: "Active" }), make("option", { value: "disabled", text: "Disabled" }));
  statusSelect.value = user.status;
  statusLabel.append(statusSelect);
  const preview = make("div", { className: "permission-preview", attributes: { "aria-live": "polite" } });
  const save = makeButton("Save access changes", "button primary");
  save.type = "submit";
  const note = make("p", { className: "security-note" });
  if (user.deletedAt) {
    append(note, make("strong", { text: "Deleted account" }), make("span", { text: "This tombstoned account is retained only for audit and historical references. It cannot be restored or granted access." }));
    roleSelect.disabled = true;
    statusSelect.disabled = true;
  } else if (user.archivedAt) {
    append(note, make("strong", { text: "Archived account" }), make("span", { text: "Restore this record before changing access. Restored users remain disabled until an owner explicitly re-enables them." }));
    roleSelect.disabled = true;
    statusSelect.disabled = true;
  } else if (isCurrentUser) {
    append(note, make("strong", { text: "Current account" }), make("span", { text: "For safety, this signed-in account cannot edit its own role or status. Sign in as another platform owner to change it." }));
    roleSelect.disabled = true;
    statusSelect.disabled = true;
  } else {
    append(note, make("strong", { text: "Immediate effect" }), make("span", { text: "Saving a role or status change revokes every active session for this user. The last active platform owner cannot be removed or disabled." }));
  }
  function syncAccessForm() {
    renderPermissionPreview(preview, roleSelect.value);
    const unchanged = roleSelect.value === user.role && statusSelect.value === user.status;
    save.disabled = isCurrentUser || Boolean(user.archivedAt) || Boolean(user.deletedAt) || unchanged;
  }
  roleSelect.addEventListener("change", syncAccessForm);
  statusSelect.addEventListener("change", syncAccessForm);
  append(form, formError, roleLabel, statusLabel, preview, note, save);
  syncAccessForm();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await updateUserAccess(user, roleSelect.value, statusSelect.value, save, formError);
  });
  access.append(form);
  byId("drawer-body").replaceChildren(...[record, lifecycleSection, access].filter(Boolean));
}

async function resendUserInvitation(user) {
  const confirmed = await confirmAction(
    "Resend this invitation?",
    `A fresh one-time password setup link will be created for ${user.email}. Any earlier setup link will stop working.`,
    "Resend invitation",
  );
  if (!confirmed) return;
  try {
    const payload = await api(`${API}/admin/users/${encodeURIComponent(user.id)}/invitation/resend`, { method: "POST" });
    closeDrawer();
    showUserInviteResult(payload, "resent");
    toast("Invitation refreshed.");
    loadUsers();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function changeUserLifecycle(user, action) {
  let confirmed;
  if (action === "archive") {
    confirmed = await confirmAction(
      "Archive this user?",
      `${user.email} will be disabled, signed out everywhere, and hidden from the current user list. Assigned licenses and existing device leases are not revoked; manage those separately. The record can be restored later, but it will remain disabled.`,
      "Archive user",
    );
  } else if (action === "restore") {
    confirmed = await confirmAction(
      "Restore this user record?",
      `${user.email} will return to the current user list but remain disabled. Review the role before explicitly re-enabling access.`,
      "Restore record",
    );
  } else {
    confirmed = await confirmAction(
      "Permanently delete this user?",
      "The archived account will be anonymized and cannot be restored. Audit and historical license references are retained. Deletion is blocked while operational licenses remain assigned. Type the complete email address to continue.",
      "Permanently delete",
      user.email,
    );
  }
  if (!confirmed) return;
  const body = { expectedRevision: user.revision };
  if (action === "delete") body.email = user.email;
  try {
    const payload = await api(`${API}/admin/users/${encodeURIComponent(user.id)}/${action}`, { method: "POST", body });
    if (action === "delete") {
      toast("User permanently deleted and anonymized. Open Deleted above to view the tombstone.");
      closeDrawer();
    } else {
      toast(action === "archive"
        ? "User archived and disabled. Open Archived above to find the account."
        : "User restored in disabled state. Open Current above to find the account.");
      await openUserDrawer(payload?.user?.id || user.id);
    }
    loadUsers();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function updateUserAccess(user, role, status, button, errorElement) {
  if (role === user.role && status === user.status) {
    toast("No access changes to save.");
    return;
  }
  setError(errorElement, null);
  const profile = roleProfile(role);
  const confirmed = await confirmAction(
    "Update user access?",
    status === "disabled"
      ? `${user.email} will be disabled, signed out on every device, and unable to authenticate.`
      : `${user.email} will receive the ${profile.label} permission bundle. Every active session for this user will be revoked.`,
    "Save changes",
  );
  if (!confirmed) return;
  button.disabled = true;
  try {
    const payload = await api(`${API}/admin/users/${encodeURIComponent(user.id)}/access`, {
      method: "POST",
      body: { role, status, expectedRevision: user.revision },
    });
    const current = payload.user;
    toast("User access updated.");
    renderUserDetails(current);
    loadUsers();
  } catch (error) {
    if (error.status === 401) {
      clearSession();
      closeDrawer();
      showLogin("Your session ended while access was being updated. Sign in again to verify the result.");
      return;
    }
    setError(errorElement, error);
  } finally {
    button.disabled = false;
  }
}

function openCreateUserDialog() {
  const form = byId("user-form");
  form.reset();
  populateRoleSelect(form.elements.role, "license_admin");
  setError(byId("user-form-error"), null);
  renderPermissionPreview(byId("create-user-role-preview"), form.elements.role.value, "New account permissions");
  byId("user-dialog").showModal();
  window.setTimeout(() => form.elements.userInviteEmail.focus(), 0);
}

async function createUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  setError(byId("user-form-error"), null);
  submit.disabled = true;
  try {
    const payload = await api(`${API}/admin/users`, {
      method: "POST",
      body: { email: String(data.get("userInviteEmail") || "").trim(), role: String(data.get("role") || "") },
    });
    byId("user-dialog").close();
    showUserInviteResult(payload);
    toast("User account created.");
    loadUsers();
  } catch (error) {
    setError(byId("user-form-error"), error);
  } finally {
    submit.disabled = false;
  }
}

function showUserInviteResult(payload, mode = "created") {
  const user = payload.user || {};
  const delivery = payload.invitationDelivery || "manual";
  const token = String(payload.developmentPasswordResetToken || "");
  const created = mode === "created";
  let message;
  if (delivery === "email") {
    message = created
      ? `${user.email || "The user"} was created. A one-time password setup link was queued for email delivery.`
      : `A fresh one-time password setup link for ${user.email || "the user"} was queued for email delivery.`;
  } else if (token) {
    message = created
      ? `${user.email || "The user"} was created. Deliver the development setup link through a secure channel.`
      : `A fresh development setup link was created for ${user.email || "the user"}. Deliver it through a secure channel.`;
  } else {
    message = created
      ? `${user.email || "The user"} was created, but invitation delivery was not queued and no setup token is available. Restore email delivery, then have the user request a password reset.`
      : `The invitation for ${user.email || "the user"} was refreshed, but delivery was not queued and no setup token is available. Restore email delivery, then resend it again.`;
  }
  const messageElement = byId("user-invite-result-message");
  messageElement.textContent = message;
  messageElement.className = delivery === "manual" && !token ? "alert warning" : "muted";
  byId("setup-link-result-kicker").textContent = created ? "User created" : "Invitation refreshed";
  byId("setup-link-result-title").textContent = created ? "Invitation ready" : "New setup link ready";
  const manualFields = byId("manual-invite-fields");
  manualFields.hidden = !token;
  if (token) {
    const setup = new URL("/reset-password", window.location.origin);
    setup.searchParams.set("token", token);
    byId("user-invite-link").textContent = setup.toString();
    byId("user-invite-token").textContent = token;
  }
  byId("user-invite-result-dialog").showModal();
}

function clearUserInviteResult() {
  byId("user-invite-link").textContent = "";
  byId("user-invite-token").textContent = "";
  byId("user-invite-result-message").textContent = "";
  byId("user-invite-result-message").className = "muted";
  byId("setup-link-result-kicker").textContent = "User created";
  byId("setup-link-result-title").textContent = "Invitation ready";
  byId("manual-invite-fields").hidden = true;
  const details = byId("manual-invite-fields").querySelector("details");
  if (details) details.open = false;
}

async function copyUserInviteLink() {
  const link = byId("user-invite-link").textContent;
  if (!link) return;
  try {
    await navigator.clipboard.writeText(link);
    toast("Password setup link copied.");
  } catch {
    toast("Clipboard access is unavailable. Select and copy the displayed link.", "error");
  }
}

function openPasswordResetRequestDialog() {
  const form = byId("password-reset-request-form");
  form.reset();
  setError(byId("password-reset-request-error"), null);
  form.elements.resetRequestEmail.value = byId("login-email").value.trim();
  byId("password-reset-request-dialog").showModal();
  window.setTimeout(() => form.elements.resetRequestEmail.focus(), 0);
}

async function requestPasswordReset(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const email = String(new FormData(form).get("resetRequestEmail") || "").trim();
  setError(byId("password-reset-request-error"), null);
  submit.disabled = true;
  try {
    const payload = await api(`${API}/auth/password-reset/request`, { method: "POST", body: { email } }, false);
    byId("password-reset-request-dialog").close();
    form.reset();
    const token = String(payload.developmentPasswordResetToken || "");
    if (token) {
      const setup = new URL("/reset-password", window.location.origin);
      setup.searchParams.set("token", token);
      byId("setup-link-result-kicker").textContent = "Development recovery";
      byId("setup-link-result-title").textContent = "Password setup link ready";
      byId("user-invite-result-message").textContent = "The request was accepted. Use this development-only link to choose a new password.";
      byId("user-invite-result-message").className = "muted";
      byId("user-invite-link").textContent = setup.toString();
      byId("user-invite-token").textContent = token;
      byId("manual-invite-fields").hidden = false;
      byId("user-invite-result-dialog").showModal();
    } else {
      toast("If that account exists, a one-time password setup link has been queued.");
    }
  } catch (error) {
    setError(byId("password-reset-request-error"), error);
  } finally {
    submit.disabled = false;
  }
}

function auditParams(includeCursor) {
  const params = new URLSearchParams({ limit: "100" });
  const data = new FormData(byId("audit-filters"));
  for (const [key, raw] of data.entries()) {
    const value = String(raw).trim();
    if (value) params.set(key, value);
  }
  if (includeCursor && state.auditCursor) params.set("beforeId", String(state.auditCursor));
  return params;
}

async function loadAudit(appendRows = false) {
  const container = byId("audit-table");
  setError(byId("audit-error"), null);
  if (!appendRows) {
    loading(container, "Loading audit events…");
    state.auditItems = [];
    state.auditCursor = null;
  }
  const more = byId("audit-more");
  more.disabled = true;
  try {
    const payload = await api(`${API}/admin/audit-events?${auditParams(appendRows).toString()}`);
    const incoming = payload.items || [];
    state.auditItems = appendRows ? [...state.auditItems, ...incoming] : incoming;
    state.auditCursor = incoming.length ? incoming[incoming.length - 1].id : null;
    renderAudit(container, state.auditItems);
    more.hidden = incoming.length < 100;
  } catch (error) {
    setError(byId("audit-error"), error);
    if (!appendRows) empty(container, "Audit log unavailable", "Adjust the filters or refresh to try again.");
    throw error;
  } finally {
    more.disabled = false;
  }
}

function renderAudit(container, items) {
  if (!items.length) {
    empty(container, "No audit events found", "No event matches the current filters.");
    return;
  }
  const { element, body } = table(["When", "Action", "Target", "Actor", "Outcome", "Request ID", "Details"]);
  for (const item of items) {
    const row = make("tr");
    const detailText = Object.keys(item.details || {}).length ? JSON.stringify(item.details) : "—";
    append(
      row,
      make("td", { text: formatDate(item.occurredAt) }),
      primaryCell(item.action, `#${item.id}`),
      primaryCell(item.targetType, shortId(item.targetId, 20)),
      primaryCell(item.actorKind, shortId(item.actorUserId, 18)),
      cellWith(badge(item.outcome)),
      make("td", { className: "mono", text: shortId(item.requestId, 16), title: item.requestId }),
      make("td", { className: "mono", text: shortId(detailText, 35), title: detailText }),
    );
    body.append(row);
  }
  container.replaceChildren(element);
}

function localDateToRFC3339(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) throw new Error("Enter a valid date and time.");
  return parsed.toISOString();
}

function newIdempotencyKey() {
  if (crypto.randomUUID) return `console-${crypto.randomUUID()}`;
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return `console-${Array.from(bytes, (item) => item.toString(16).padStart(2, "0")).join("")}`;
}

function resetLicenseForm() {
  const form = byId("license-form");
  form.reset();
  form.elements.entitlements.value = "{}";
  form.elements.maxActivations.value = "1";
  form.elements.offlineGraceHours.value = "24";
  form.elements.idempotencyKey.value = newIdempotencyKey();
}

async function openLicenseDialog() {
  try {
    await ensureProducts(false);
    if (!state.products.some((item) => item.status === "active")) {
      toast("Create an active product before issuing a license.", "error");
      return;
    }
    resetLicenseForm();
    setError(byId("license-form-error"), null);
    byId("license-dialog").showModal();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function issueLicense(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  setError(byId("license-form-error"), null);
  submit.disabled = true;
  try {
    let entitlements;
    try {
      entitlements = JSON.parse(String(data.get("entitlements") || "{}"));
      if (!entitlements || Array.isArray(entitlements) || typeof entitlements !== "object") throw new Error();
    } catch {
      throw new Error("Entitlements must be a valid JSON object.");
    }
    const perpetual = data.get("perpetual") === "on";
    const expiresAt = localDateToRFC3339(String(data.get("expiresAt") || ""));
    if (perpetual && expiresAt) throw new Error("A perpetual license cannot have an expiration date.");
    if (!perpetual && !expiresAt) throw new Error("Choose an expiration or mark the license perpetual.");
    const body = {
      productCode: String(data.get("productCode")),
      subject: String(data.get("subject") || "").trim(),
      maxActivations: Number(data.get("maxActivations")),
      offlineGraceSeconds: Number(data.get("offlineGraceHours")) * 3600,
      perpetual,
      entitlements,
    };
    const notBefore = localDateToRFC3339(String(data.get("notBefore") || ""));
    if (notBefore) body.notBefore = notBefore;
    if (expiresAt) body.expiresAt = expiresAt;
    const payload = await api(`${API}/admin/licenses`, {
      method: "POST",
      headers: { "Idempotency-Key": String(data.get("idempotencyKey")).trim() },
      body,
    });
    form.reset();
    form.elements.idempotencyKey.value = "";
    byId("license-dialog").close();
    byId("claim-code").textContent = payload.claimCode;
    byId("claim-warning").textContent = payload.warning || "Store this code securely; the server does not retain the plaintext value.";
    byId("claim-dialog").showModal();
    toast(payload.idempotent ? "Existing license recovered idempotently." : "License issued successfully.");
    loadLicenses();
  } catch (error) {
    setError(byId("license-form-error"), error);
  } finally {
    submit.disabled = false;
  }
}

async function importLicense(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  setError(byId("import-form-error"), null);
  submit.disabled = true;
  try {
    const artifact = String(new FormData(form).get("artifact") || "").trim();
    const payload = await api(`${API}/admin/licenses/import`, { method: "POST", body: { artifact } });
    byId("import-dialog").close();
    form.reset();
    toast(payload.idempotent ? "License was already imported." : "Offline license verified and imported.");
    loadLicenses();
  } catch (error) {
    setError(byId("import-form-error"), error);
  } finally {
    submit.disabled = false;
  }
}

async function createProduct(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  setError(byId("product-form-error"), null);
  submit.disabled = true;
  try {
    await api(`${API}/admin/products`, {
      method: "POST",
      body: {
        code: String(data.get("code")).trim().toUpperCase(),
        name: String(data.get("name")).trim(),
        description: String(data.get("description") || "").trim(),
      },
    });
    byId("product-dialog").close();
    form.reset();
    toast("Product created.");
    loadProductsPage();
  } catch (error) {
    setError(byId("product-form-error"), error);
  } finally {
    submit.disabled = false;
  }
}

async function registerIssuer(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const data = new FormData(form);
  submit.disabled = true;
  try {
    const body = {
      issuer: String(data.get("issuer")).trim(),
      publicKeyDocument: String(data.get("publicKeyDocument")).trim(),
    };
    const notBefore = localDateToRFC3339(String(data.get("notBefore") || ""));
    const notAfter = localDateToRFC3339(String(data.get("notAfter") || ""));
    if (notBefore) body.notBefore = notBefore;
    if (notAfter) body.notAfter = notAfter;
    const payload = await api(`${API}/admin/issuers`, { method: "POST", body });
    form.reset();
    toast("Offline issuer key registered.");
    const keyId = payload.issuerKey?.keyId;
    if (keyId) {
      byId("issuer-status-form").elements.keyId.value = keyId;
      configureIssuerStatusForm(payload.issuerKey);
    }
    loadIssuers();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    submit.disabled = false;
  }
}

async function updateIssuerStatus(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const keyId = form.elements.keyId.value.trim();
  const issuer = state.issuers.find((item) => item.keyId === keyId);
  if (issuer?.status === "revoked") {
    configureIssuerStatusForm(issuer);
    toast("A revoked issuer key cannot be reactivated or retired.", "error");
    return;
  }
  const status = form.elements.status.value;
  const destructive = status === "revoked";
  const confirmed = await confirmAction(
    `${status[0].toUpperCase()}${status.slice(1)} issuer key?`,
    destructive
      ? "Revocation signals that this key is no longer trusted. Confirm only if this is intentional."
      : `The issuer key will be changed to ${status}.`,
    "Update key",
  );
  if (!confirmed) return;
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await api(`${API}/admin/issuers/${encodeURIComponent(keyId)}/status`, { method: "POST", body: { status } });
    toast(`Issuer key changed to ${status}.`);
    await loadIssuers();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    const current = state.issuers.find((item) => item.keyId === keyId);
    if (current) configureIssuerStatusForm(current);
    else submit.disabled = false;
  }
}

function confirmAction(title, message, acceptLabel, expectedText = "") {
  const dialog = byId("confirm-dialog");
  const typedGroup = byId("confirm-typed-group");
  const typedInput = byId("confirm-typed-input");
  const accept = byId("confirm-accept");
  byId("confirm-title").textContent = title;
  byId("confirm-message").textContent = message;
  accept.textContent = acceptLabel;
  typedInput.value = "";
  typedGroup.hidden = !expectedText;
  typedInput.required = Boolean(expectedText);
  byId("confirm-typed-label").textContent = expectedText
    ? `Type ${expectedText} to confirm`
    : "Type the record identifier to confirm";
  accept.disabled = Boolean(expectedText);
  typedInput.oninput = () => {
    accept.disabled = typedInput.value !== expectedText;
  };
  dialog.querySelector("form").onsubmit = (event) => {
    if (expectedText && typedInput.value !== expectedText) event.preventDefault();
  };
  dialog.returnValue = "cancel";
  dialog.showModal();
  if (expectedText) window.setTimeout(() => typedInput.focus(), 0);
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      typedInput.oninput = null;
      dialog.querySelector("form").onsubmit = null;
      typedInput.value = "";
      typedGroup.hidden = true;
      typedInput.required = false;
      accept.disabled = false;
      resolve(dialog.returnValue === "confirm");
    }, { once: true });
  });
}

async function copyClaimCode() {
  const value = byId("claim-code").textContent;
  try {
    await navigator.clipboard.writeText(value);
    toast("Claim code copied.");
  } catch {
    toast("Clipboard access is unavailable. Select and copy the displayed code.", "error");
  }
}

function clearClaimCode() {
  const code = byId("claim-code");
  const warning = byId("claim-warning");
  if (code) code.textContent = "";
  if (warning) warning.textContent = "";
}

function setSidebarOpen(open, restoreFocus = true) {
  const sidebar = byId("sidebar");
  const workspace = document.querySelector(".workspace");
  const backdrop = byId("sidebar-backdrop");
  const toggle = byId("menu-toggle");
  if (!sidebar || !workspace || !backdrop || !toggle) return;
  const shouldOpen = Boolean(open && mobileNavigation.matches);
  sidebar.classList.toggle("open", shouldOpen);
  toggle.setAttribute("aria-expanded", String(shouldOpen));
  backdrop.hidden = !shouldOpen;
  if (mobileNavigation.matches) {
    sidebar.toggleAttribute("inert", !shouldOpen);
    workspace.toggleAttribute("inert", shouldOpen);
  } else {
    sidebar.removeAttribute("inert");
    workspace.removeAttribute("inert");
  }
  if (shouldOpen) {
    const active = sidebar.querySelector("button.active:not([hidden])") || sidebar.querySelector("button:not([hidden])");
    window.setTimeout(() => active?.focus(), 0);
  } else if (restoreFocus && mobileNavigation.matches) {
    toggle.focus();
  }
}

function bindEvents() {
  byId("login-form").addEventListener("submit", handleLogin);
  byId("open-registration-button").addEventListener("click", openRegistrationDialog);
  byId("registration-form").addEventListener("submit", registerCustomer);
  byId("copy-verification-link").addEventListener("click", copyVerificationLink);
  byId("email-verification-form").addEventListener("submit", completeEmailVerification);
  byId("email-verification-continue").addEventListener("click", () => showLogin());
  byId("resend-verification-button").addEventListener("click", resendVerification);
  byId("request-password-reset-button").addEventListener("click", openPasswordResetRequestDialog);
  byId("password-reset-request-form").addEventListener("submit", requestPasswordReset);
  byId("password-setup-form").addEventListener("submit", completePasswordSetup);
  byId("password-setup-continue").addEventListener("click", () => showLogin("Password saved. Sign in to continue."));
  byId("password-setup-return").addEventListener("click", () => {
    passwordSetupToken = "";
    byId("password-setup-form").reset();
    showLogin();
  });
  byId("logout-button").addEventListener("click", logout);
  byId("account-security-button").addEventListener("click", openAccountSecurity);
  byId("account-password-form").addEventListener("submit", changeOwnPassword);
  byId("refresh-account-sessions").addEventListener("click", loadAccountSessions);
  byId("revoke-other-sessions").addEventListener("click", revokeOtherSessions);
  byId("dashboard-refresh").addEventListener("click", loadDashboard);
  byId("machines-refresh").addEventListener("click", loadMachines);
  byId("drawer-close").addEventListener("click", closeDrawer);
  byId("drawer-backdrop").addEventListener("click", closeDrawer);
  byId("menu-toggle").addEventListener("click", () => setSidebarOpen(!byId("sidebar").classList.contains("open")));
  byId("sidebar-backdrop").addEventListener("click", () => setSidebarOpen(false));
  for (const button of document.querySelectorAll("[data-route]")) {
    button.addEventListener("click", () => navigate(button.dataset.route));
  }
  for (const button of document.querySelectorAll("[data-go]")) {
    button.addEventListener("click", () => navigate(button.dataset.go));
  }
  for (const button of document.querySelectorAll("[data-lifecycle-form]")) {
    button.addEventListener("click", () => selectLifecycle(button));
  }
  for (const button of document.querySelectorAll("[data-close-dialog]")) {
    button.addEventListener("click", () => byId(button.dataset.closeDialog).close());
  }
  byId("license-filters").addEventListener("submit", (event) => { event.preventDefault(); loadLicenses(); });
  byId("clear-license-filters").addEventListener("click", () => { byId("license-filters").reset(); loadLicenses(); });
  byId("request-filters").addEventListener("submit", (event) => { event.preventDefault(); loadRequests(); });
  byId("clear-request-filters").addEventListener("click", () => { byId("request-filters").reset(); loadRequests(); });
  byId("machine-filters").addEventListener("submit", (event) => { event.preventDefault(); loadMachines(); });
  byId("clear-machine-filters").addEventListener("click", () => { byId("machine-filters").reset(); loadMachines(); });
  byId("user-search").addEventListener("submit", (event) => { event.preventDefault(); loadUsers(); });
  byId("clear-user-search").addEventListener("click", () => { byId("user-search").reset(); loadUsers(); });
  byId("audit-filters").addEventListener("submit", (event) => { event.preventDefault(); loadAudit(false); });
  byId("clear-audit-filters").addEventListener("click", () => { byId("audit-filters").reset(); loadAudit(false); });
  byId("audit-more").addEventListener("click", () => loadAudit(true));
  byId("create-license-button").addEventListener("click", openLicenseDialog);
  byId("create-request-button").addEventListener("click", openLicenseRequestDialog);
  byId("claim-license-button").addEventListener("click", openClaimLicenseDialog);
  byId("entitlements-help-button").addEventListener("click", () => byId("entitlements-guide-dialog").showModal());
  byId("import-license-button").addEventListener("click", () => { setError(byId("import-form-error"), null); byId("import-dialog").showModal(); });
  byId("create-product-button").addEventListener("click", () => { setError(byId("product-form-error"), null); byId("product-dialog").showModal(); });
  byId("create-user-button").addEventListener("click", openCreateUserDialog);
  byId("license-form").addEventListener("submit", issueLicense);
  byId("license-request-form").addEventListener("submit", createLicenseRequest);
  byId("claim-license-form").addEventListener("submit", claimLicense);
  byId("import-form").addEventListener("submit", importLicense);
  byId("product-form").addEventListener("submit", createProduct);
  byId("user-form").addEventListener("submit", createUser);
  byId("user-form").elements.role.addEventListener("change", (event) => renderPermissionPreview(byId("create-user-role-preview"), event.currentTarget.value, "New account permissions"));
  byId("issuer-form").addEventListener("submit", registerIssuer);
  byId("issuer-status-form").addEventListener("submit", updateIssuerStatus);
  byId("issuer-status-form").elements.keyId.addEventListener("input", (event) => {
    configureIssuerStatusForm(state.issuers.find((item) => item.keyId === event.currentTarget.value.trim()) || null);
  });
  byId("copy-claim-code").addEventListener("click", copyClaimCode);
  byId("copy-user-invite-link").addEventListener("click", copyUserInviteLink);
  byId("claim-dialog").addEventListener("close", clearClaimCode);
  byId("user-dialog").addEventListener("close", () => {
    byId("user-form").reset();
    setError(byId("user-form-error"), null);
  });
  byId("password-reset-request-dialog").addEventListener("close", () => {
    byId("password-reset-request-form").reset();
    setError(byId("password-reset-request-error"), null);
  });
  byId("user-invite-result-dialog").addEventListener("close", clearUserInviteResult);
  byId("account-security-dialog").addEventListener("close", () => {
    listRequests.sessions += 1;
    byId("account-password-form").reset();
    setError(byId("account-password-error"), null);
    setError(byId("account-sessions-error"), null);
    const status = byId("account-password-status");
    status.hidden = true;
    status.textContent = "";
  });
  byId("registration-dialog").addEventListener("close", () => {
    byId("registration-form").reset();
    setError(byId("registration-error"), null);
    byId("registration-entry").hidden = false;
    byId("registration-complete").hidden = true;
    byId("development-verification-fields").hidden = true;
    byId("development-verification-link").textContent = "";
    byId("registration-submit").hidden = false;
  });
  byId("license-request-dialog").addEventListener("close", () => {
    byId("license-request-form").reset();
    setError(byId("license-request-form-error"), null);
  });
  byId("claim-license-dialog").addEventListener("close", () => {
    byId("claim-license-form").reset();
    setError(byId("claim-license-error"), null);
  });
  mobileNavigation.addEventListener("change", () => setSidebarOpen(false, false));
  window.addEventListener("hashchange", () => navigate(location.hash.slice(1), true));
  document.addEventListener("keydown", (event) => {
    if (document.querySelector("dialog[open]")) return;
    const drawer = byId("detail-drawer");
    const sidebar = byId("sidebar");
    if (event.key === "Escape" && drawer.classList.contains("open")) {
      closeDrawer();
      return;
    }
    if (event.key === "Escape" && sidebar.classList.contains("open")) {
      setSidebarOpen(false);
      return;
    }
    if (event.key === "Tab" && sidebar.classList.contains("open")) {
      const sidebarItems = Array.from(sidebar.querySelectorAll('button:not([disabled]):not([hidden]), a[href]'));
      const first = sidebarItems[0];
      const last = sidebarItems[sidebarItems.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
      return;
    }
    if (event.key !== "Tab" || !drawer.classList.contains("open")) return;
    const focusable = Array.from(
      drawer.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'),
    ).filter((item) => !item.hidden);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
}

async function initialize() {
  const setup = takePasswordSetupIntent();
  const verification = setup.requested ? { requested: false, token: "" } : takeEmailVerificationIntent();
  bindEvents();
  renderRoleGuide();
  await loadPublicConfig();
  if (setup.requested) {
    clearSession();
    passwordSetupToken = setup.token;
    showPasswordSetup(passwordSetupToken);
    return;
  }
  if (verification.requested) {
    clearSession();
    showEmailVerification(verification.token);
    return;
  }
  if (!state.refreshToken) {
    showLogin();
    return;
  }
  try {
    const accessExpiry = new Date(state.accessExpiresAt).valueOf();
    if (!state.accessToken || !accessExpiry || accessExpiry - Date.now() < 60000) await refreshSession();
    const payload = await api(`${API}/auth/me`);
    if (payload?.user?.emailVerifiedAt === null) {
      const email = payload.user.email || "";
      clearSession();
      byId("login-email").value = email;
      showLogin("Verify your email and choose a password before signing in. You can request a fresh verification email below.");
      return;
    }
    state.user = payload.user;
    storeSession({ user: payload.user });
    showApp();
    try {
      await ensureProducts(false);
    } catch {
      // Individual pages surface catalog errors where relevant.
    }
    navigate(location.hash.slice(1) || "dashboard", true);
  } catch {
    clearSession();
    showLogin("Sign in to continue.");
  }
}

window.setInterval(() => {
  if (!state.refreshToken || byId("app-shell").hidden) return;
  const expires = new Date(state.accessExpiresAt).valueOf();
  if (!expires || expires - Date.now() < 120000) refreshSession().catch(() => {});
}, 30000);

initialize();
