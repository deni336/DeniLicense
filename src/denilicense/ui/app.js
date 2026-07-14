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
  machines: [],
  auditItems: [],
  auditCursor: null,
  route: "dashboard",
  drawerReturnFocus: null,
};

const routes = {
  dashboard: { title: "Overview", kicker: "Operations", roles: null },
  licenses: { title: "Licenses", kicker: "Inventory", roles: null },
  machines: {
    title: "Machines",
    kicker: "Installations",
    roles: ["platform_owner", "license_admin", "support", "auditor"],
  },
  products: {
    title: "Products",
    kicker: "Catalog",
    roles: ["platform_owner", "license_admin"],
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
      "Suspend or revoke licenses",
      "Create products",
      "Deactivate machine activations",
    ],
  },
  support: {
    label: "Support",
    summary: "Investigates customer and machine issues without issuance access.",
    permissions: [
      "View all license owners and licenses",
      "View machine activation details",
      "Deactivate machine activations",
      "View operational dashboard totals",
    ],
  },
  auditor: {
    label: "Auditor",
    summary: "Read-only oversight of licensing activity and security events.",
    permissions: [
      "View all licenses and machines",
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
      "Activate licensed machines",
      "View and deactivate own activations",
      "No administrative access",
    ],
  },
});

let refreshPromise = null;
let routeRequest = 0;
let passwordSetupToken = "";
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
  container.replaceChildren(make("div", { className: "loading-state", text: label }));
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
  state.machines = [];
  passwordSetupToken = "";
  for (const key of Object.values(SESSION_KEYS)) sessionStorage.removeItem(key);
  clearClaimCode();
  clearUserInviteResult();
  for (const id of ["user-dialog", "user-invite-result-dialog", "password-reset-request-dialog"]) {
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

function canDeactivate() {
  return hasRole("platform_owner", "license_admin", "support");
}

function showLogin(message = "") {
  closeDrawer();
  setSidebarOpen(false, false);
  byId("app-shell").hidden = true;
  byId("password-setup-screen").hidden = true;
  byId("login-screen").hidden = false;
  setError(byId("login-error"), message ? new Error(message) : null);
  window.setTimeout(() => byId("login-email").focus(), 0);
}

function showApp() {
  byId("login-screen").hidden = true;
  byId("password-setup-screen").hidden = true;
  byId("app-shell").hidden = false;
  const email = state.user?.email || "Account";
  byId("user-email").textContent = email;
  byId("user-role").textContent = (state.user?.role || "").replaceAll("_", " ");
  byId("user-avatar").textContent = email.slice(0, 2).toUpperCase();
  for (const button of document.querySelectorAll("[data-roles]")) {
    const rolesForButton = button.dataset.roles.split(",");
    button.hidden = !rolesForButton.includes(state.user?.role);
  }
  byId("license-actions").hidden = !isLicenseWriter();
  byId("license-filters").hidden = !isManagementReader();
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

function showPasswordSetup(token) {
  closeDrawer();
  setSidebarOpen(false, false);
  byId("login-screen").hidden = true;
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
    form.reset();
    showApp();
    navigate(location.hash.slice(1) || "dashboard", true);
  } catch (error) {
    setError(byId("login-error"), error);
  } finally {
    submit.disabled = false;
    submit.classList.remove("loading");
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
    else location.hash = target;
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
  if (isLicenseWriter()) {
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
  const container = byId("licenses-table");
  setError(byId("licenses-error"), null);
  loading(container, "Loading licenses…");
  try {
    await ensureProducts(false);
    const endpoint = isManagementReader()
      ? `${API}/admin/licenses?${getLicenseQuery().toString()}`
      : `${API}/licenses`;
    const payload = await api(endpoint);
    state.licenses = payload.items || [];
    byId("license-result-summary").textContent = `${state.licenses.length.toLocaleString()} license${state.licenses.length === 1 ? "" : "s"} shown`;
    renderLicenseTable(container, state.licenses);
  } catch (error) {
    setError(byId("licenses-error"), error);
    empty(container, "Licenses unavailable", "Adjust the filters or refresh to try again.");
    throw error;
  }
}

function table(headers) {
  const element = make("table");
  const head = make("thead");
  const row = make("tr");
  for (const header of headers) row.append(make("th", { text: header }));
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

function renderLicenseTable(container, licenses, options = {}) {
  if (!licenses.length) {
    empty(container, "No licenses found", "No license matches the current view or filters.");
    return;
  }
  const headers = options.compact
    ? ["Serial", "Product", "Owner", "State", "Expires", ""]
    : ["License", "Product", "Owner", "Source", "Seats", "State", "Expires", ""];
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
        make("td", { text: license.expiresAt ? formatDate(license.expiresAt, false) : "Perpetual" }),
      );
    }
    const actionCell = make("td");
    actionCell.append(makeButton("View", "button secondary", (event) => openLicenseDrawer(license.id, event.currentTarget)));
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
  );
  overview.append(overviewGrid);
  if (isLicenseWriter()) {
    const actions = make("div", { className: "detail-actions" });
    for (const nextState of ["active", "suspended", "revoked"]) {
      if (nextState === license.state) continue;
      const label = nextState === "active" ? "Restore active" : `${nextState[0].toUpperCase()}${nextState.slice(1)}`;
      actions.append(
        makeButton(label, nextState === "revoked" ? "button danger-outline" : "button secondary", () => changeLicenseState(license, nextState)),
      );
    }
    overview.append(actions);
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

  const activeMachines = activations.filter((item) => item.state === "active").length;
  const machines = detailSection(
    `Machines (${activeMachines}/${license.maxActivations} active · ${activations.length} total records)`,
  );
  if (!activations.length) {
    machines.append(make("p", { className: "muted", text: "This license has not been activated on a machine." }));
  } else {
    for (const activation of activations) machines.append(renderMachineCard(activation, license));
  }
  body.replaceChildren(overview, entitlements, machines);
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

async function deactivateMachine(activation, license = null) {
  const confirmed = await confirmAction(
    "Deactivate this machine?",
    `${activation.label || "This machine"} will lose its activation. The license seat will become available.`,
    "Deactivate machine",
  );
  if (!confirmed) return;
  try {
    await api(`${API}/admin/activations/${encodeURIComponent(activation.id)}`, { method: "DELETE" });
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
  const container = byId("machines-table");
  setError(byId("machines-error"), null);
  loading(container, "Loading machine installations…");
  try {
    await ensureProducts(false);
    const payload = await api(`${API}/admin/activations?${getMachineQuery().toString()}`);
    state.machines = payload.items || [];
    byId("machine-result-summary").textContent = `${state.machines.length.toLocaleString()} installation${state.machines.length === 1 ? "" : "s"} shown`;
    renderMachinesTable(container, state.machines);
  } catch (error) {
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
  const container = byId("products-table");
  setError(byId("products-error"), null);
  loading(container, "Loading products…");
  try {
    const products = await ensureProducts(true);
    renderProducts(container, products);
  } catch (error) {
    setError(byId("products-error"), error);
    empty(container, "Products unavailable", "Refresh to try again.");
    throw error;
  }
}

function renderProducts(container, products) {
  if (!products.length) {
    empty(container, "No products yet", "Create a product before issuing licenses.");
    return;
  }
  const { element, body } = table(["Product", "Code", "Description", "Status", "Created"]);
  for (const product of products) {
    const row = make("tr");
    append(
      row,
      primaryCell(product.name),
      make("td", { className: "mono", text: product.code }),
      primaryCell(product.description || "—"),
      cellWith(badge(product.status)),
      make("td", { text: formatDate(product.createdAt, false) }),
    );
    body.append(row);
  }
  container.replaceChildren(element);
}

async function loadIssuers() {
  const result = byId("issuer-result");
  try {
    const payload = await api(`${API}/admin/issuers?limit=200`);
    renderIssuerResult(result, payload.items || []);
  } catch (error) {
    if (error.status === 404 || error.status === 405) {
      result.hidden = false;
      result.textContent = "Registered keys can be managed by key ID. Issuer inventory is unavailable on this server version.";
      return;
    }
    toast(error.message, "error");
  }
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
      form.elements.status.value = issuer.status;
      form.elements.status.focus();
    });
    append(card, head, dates, manage);
    container.append(card);
  }
}

async function loadUsers() {
  const container = byId("users-table");
  setError(byId("users-error"), null);
  loading(container, "Loading users…");
  const email = String(new FormData(byId("user-search")).get("userEmailSearch") || "").trim();
  const params = new URLSearchParams({ limit: "200" });
  if (email) params.set("email", email);
  try {
    const payload = await api(`${API}/admin/users?${params.toString()}`);
    renderUsers(container, payload.items || []);
  } catch (error) {
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
  const { element, body } = table(["User", "Role", "Verification", "Status", "Created", ""]);
  for (const user of users) {
    const row = make("tr");
    append(
      row,
      primaryCell(user.email, shortId(user.id, 18)),
      cellWith(badge(roleProfile(user.role).label)),
      make("td", { text: user.emailVerifiedAt ? formatDate(user.emailVerifiedAt) : "Not verified" }),
      cellWith(badge(user.status)),
      make("td", { text: formatDate(user.createdAt, false) }),
    );
    const actions = make("td");
    actions.append(makeButton("Manage", "button secondary", (event) => openUserDrawer(user.id, event.currentTarget)));
    row.append(actions);
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
    detailField("Email verified", user.emailVerifiedAt ? formatDate(user.emailVerifiedAt) : "Not verified"),
    detailField("Created", formatDate(user.createdAt)),
  );
  record.append(grid);

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
  if (isCurrentUser) {
    append(note, make("strong", { text: "Current account" }), make("span", { text: "For safety, this signed-in account cannot edit its own role or status. Sign in as another platform owner to change it." }));
    roleSelect.disabled = true;
    statusSelect.disabled = true;
  } else {
    append(note, make("strong", { text: "Immediate effect" }), make("span", { text: "Saving a role or status change revokes every active session for this user. The last active platform owner cannot be removed or disabled." }));
  }
  function syncAccessForm() {
    renderPermissionPreview(preview, roleSelect.value);
    const unchanged = roleSelect.value === user.role && statusSelect.value === user.status;
    save.disabled = isCurrentUser || unchanged;
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
  byId("drawer-body").replaceChildren(record, access);
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
    const payload = await api(`${API}/admin/users/${encodeURIComponent(user.id)}/access`, { method: "POST", body: { role, status } });
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

function showUserInviteResult(payload) {
  const user = payload.user || {};
  const delivery = payload.invitationDelivery || "manual";
  const token = String(payload.developmentPasswordResetToken || "");
  let message;
  if (delivery === "email") {
    message = `${user.email || "The user"} was created. A one-time password setup link was queued for email delivery.`;
  } else if (token) {
    message = `${user.email || "The user"} was created. Deliver the development setup link through a secure channel.`;
  } else {
    message = `${user.email || "The user"} was created, but invitation delivery was not queued and no setup token is available. Restore email delivery, then have the user request a password reset.`;
  }
  const messageElement = byId("user-invite-result-message");
  messageElement.textContent = message;
  messageElement.className = delivery === "manual" && !token ? "alert warning" : "muted";
  byId("setup-link-result-kicker").textContent = "User created";
  byId("setup-link-result-title").textContent = "Invitation ready";
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

async function openLicenseDialog() {
  try {
    await ensureProducts(false);
    if (!state.products.some((item) => item.status === "active")) {
      toast("Create an active product before issuing a license.", "error");
      return;
    }
    const form = byId("license-form");
    form.elements.idempotencyKey.value = newIdempotencyKey();
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
    if (keyId) byId("issuer-status-form").elements.keyId.value = keyId;
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
  const data = new FormData(form);
  const keyId = String(data.get("keyId")).trim();
  const status = String(data.get("status"));
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
    loadIssuers();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    submit.disabled = false;
  }
}

function confirmAction(title, message, acceptLabel) {
  const dialog = byId("confirm-dialog");
  byId("confirm-title").textContent = title;
  byId("confirm-message").textContent = message;
  byId("confirm-accept").textContent = acceptLabel;
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
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
  for (const button of document.querySelectorAll("[data-close-dialog]")) {
    button.addEventListener("click", () => byId(button.dataset.closeDialog).close());
  }
  byId("license-filters").addEventListener("submit", (event) => { event.preventDefault(); loadLicenses(); });
  byId("clear-license-filters").addEventListener("click", () => { byId("license-filters").reset(); loadLicenses(); });
  byId("machine-filters").addEventListener("submit", (event) => { event.preventDefault(); loadMachines(); });
  byId("clear-machine-filters").addEventListener("click", () => { byId("machine-filters").reset(); loadMachines(); });
  byId("user-search").addEventListener("submit", (event) => { event.preventDefault(); loadUsers(); });
  byId("clear-user-search").addEventListener("click", () => { byId("user-search").reset(); loadUsers(); });
  byId("audit-filters").addEventListener("submit", (event) => { event.preventDefault(); loadAudit(false); });
  byId("clear-audit-filters").addEventListener("click", () => { byId("audit-filters").reset(); loadAudit(false); });
  byId("audit-more").addEventListener("click", () => loadAudit(true));
  byId("create-license-button").addEventListener("click", openLicenseDialog);
  byId("import-license-button").addEventListener("click", () => { setError(byId("import-form-error"), null); byId("import-dialog").showModal(); });
  byId("create-product-button").addEventListener("click", () => { setError(byId("product-form-error"), null); byId("product-dialog").showModal(); });
  byId("create-user-button").addEventListener("click", openCreateUserDialog);
  byId("license-form").addEventListener("submit", issueLicense);
  byId("import-form").addEventListener("submit", importLicense);
  byId("product-form").addEventListener("submit", createProduct);
  byId("user-form").addEventListener("submit", createUser);
  byId("user-form").elements.role.addEventListener("change", (event) => renderPermissionPreview(byId("create-user-role-preview"), event.currentTarget.value, "New account permissions"));
  byId("issuer-form").addEventListener("submit", registerIssuer);
  byId("issuer-status-form").addEventListener("submit", updateIssuerStatus);
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
  bindEvents();
  renderRoleGuide();
  if (setup.requested) {
    clearSession();
    passwordSetupToken = setup.token;
    showPasswordSetup(passwordSetupToken);
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
