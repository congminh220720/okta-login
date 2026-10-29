import { styles } from "./styles";

// Shape of the object Auth0 injects as base64 '@@config@@' into Custom Login Page HTML.
export type Auth0PageConfig = {
  auth0Domain: string;
  clientID: string;
  callbackURL: string;
  auth0Tenant?: string;
  authorizationServer?: { issuer?: string };
  internalOptions?: Record<string, unknown>;
  extraParams?: { login_hint?: unknown };
};

export type Auth0LoginError = {
  code?: string;
  error?: string;
  description?: string;
  error_description?: string;
} | null;

type Captcha = { getValue(): string; reload(): void };

export interface WebAuthLike {
  login(
    options: { realm: string; username: string; password: string; captcha?: string },
    callback: (error: Auth0LoginError) => void,
  ): void;
  renderCaptcha?(element: HTMLElement): Captcha;
}

export type MountOptions = {
  auth0Config: Auth0PageConfig;
  /** Absolute URL of the lab app's POST /api/auth/resolve-connection endpoint. */
  resolveUrl: string;
  /** Absolute URL of POST /api/auth/forgot-password. Omit to hide "Forgot your password?". */
  forgotPasswordUrl?: string;
  connections?: string[];
  signupUrl?: string;
  /** Test seam; defaults to `new auth0.WebAuth(...)` from the auth0.js CDN script. */
  webAuth?: WebAuthLike;
  fetch?: typeof fetch;
};

type ResolveResult =
  | { ok: true; connection: string }
  | { ok: false; reason: "not_found" | "rate_limited" | "unavailable" };

const USERNAME = /^[a-z0-9._-]{1,128}$/;
const DEFAULT_CONNECTIONS = ["devdb", "ecomdb"];

export const messages = {
  invalidUsername: "Enter a username (letters, numbers, dots, underscores or hyphens). Email login is not supported.",
  missingPassword: "Enter your password.",
  credentials: "Unable to sign in with these credentials.",
  rateLimited: "Too many attempts. Please wait 5 minutes and try again.",
  unavailable: "Could not reach the lab app to find your account. Make sure it is running, then try again.",
  blocked: "This account is temporarily blocked after too many attempts. Try again later or contact an administrator.",
  captcha: "Complete the verification challenge and try again.",
  leaked: "This password was found in a data breach. Reset your password before signing in.",
  generic: "Sign-in failed. Please try again.",
  setup: "Login page is not configured correctly. Contact the administrator.",
  resetSent: "If an account with that username has an email address, Auth0 has sent a password reset link. Check your inbox and spam folder.",
  resetRateLimited: "Too many requests. Please wait 15 minutes and try again.",
  resetUnavailable: "Could not request a password reset right now. Make sure the lab app is running, then try again.",
};

export type ResetResult = { ok: true } | { ok: false; reason: "rate_limited" | "unavailable" };

export async function requestPasswordReset(
  username: string,
  url: string,
  fetcher: typeof fetch,
): Promise<ResetResult> {
  try {
    const response = await fetcher(url, {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
      signal: AbortSignal.timeout(15_000),
    });
    if (response.ok) return { ok: true };
    return { ok: false, reason: response.status === 429 ? "rate_limited" : "unavailable" };
  } catch {
    return { ok: false, reason: "unavailable" };
  }
}

export function normalizeUsername(value: string): string | undefined {
  const username = value.trim().toLowerCase();
  return USERNAME.test(username) ? username : undefined;
}

export function auth0ErrorMessage(error: Auth0LoginError): string {
  const code = error?.code ?? error?.error ?? "";
  if (["access_denied", "invalid_user_password", "invalid_grant", "invalid_signup"].includes(code)) {
    return messages.credentials;
  }
  if (["too_many_attempts", "blocked_user"].includes(code)) return messages.blocked;
  if (code === "invalid_captcha") return messages.captcha;
  if (code === "password_leaked") return messages.leaked;
  return messages.generic;
}

export async function resolveConnection(
  username: string,
  resolveUrl: string,
  allowed: string[],
  fetcher: typeof fetch,
): Promise<ResolveResult> {
  let response: Response;
  try {
    response = await fetcher(resolveUrl, {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return { ok: false, reason: "unavailable" };
  }
  if (response.status === 404) return { ok: false, reason: "not_found" };
  if (response.status === 429) return { ok: false, reason: "rate_limited" };
  if (!response.ok) return { ok: false, reason: "unavailable" };
  try {
    const body: unknown = await response.json();
    const connection = typeof body === "object" && body !== null && "connection" in body
      ? body.connection : undefined;
    if (typeof connection === "string" && allowed.includes(connection)) return { ok: true, connection };
  } catch {
    return { ok: false, reason: "unavailable" };
  }
  return { ok: false, reason: "unavailable" };
}

export function createWebAuth(config: Auth0PageConfig): WebAuthLike {
  const auth0 = (globalThis as { auth0?: { WebAuth: new (params: object) => WebAuthLike } }).auth0;
  if (!auth0?.WebAuth) throw new Error("auth0.js is not loaded");
  const internal: Record<string, unknown> = { ...(config.internalOptions ?? {}) };
  if (internal.leeway !== undefined) {
    const leeway = Number.parseInt(String(internal.leeway), 10);
    if (!Number.isNaN(leeway)) internal.leeway = leeway;
  }
  return new auth0.WebAuth({
    overrides: { __tenant: config.auth0Tenant, __token_issuer: config.authorizationServer?.issuer },
    domain: config.auth0Domain,
    clientID: config.clientID,
    redirectUri: config.callbackURL,
    responseType: "code",
    ...internal,
  });
}

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string>> = {},
  ...children: (Node | string | null | undefined)[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value !== undefined) element.setAttribute(key, value);
  }
  for (const child of children) {
    if (child !== null && child !== undefined) element.append(child);
  }
  return element;
}

function safeHttpUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}

function injectStyles() {
  if (document.getElementById("lab-hosted-styles")) return;
  const style = document.createElement("style");
  style.id = "lab-hosted-styles";
  style.textContent = styles;
  document.head.append(style);
}

export function mount(root: HTMLElement, options: MountOptions) {
  injectStyles();
  const connections = options.connections?.length ? options.connections : DEFAULT_CONNECTIONS;
  const fetcher = options.fetch ?? fetch.bind(globalThis);
  const signupUrl = safeHttpUrl(options.signupUrl);
  const forgotUrl = safeHttpUrl(options.forgotPasswordUrl);

  const errorBox = h("div", { "aria-live": "polite", "aria-atomic": "true" });
  const username = h("input", {
    id: "lab-username", name: "username", autocomplete: "username", autocapitalize: "none",
    spellcheck: "false", maxlength: "128", required: "", "aria-describedby": "lab-username-hint",
  });
  const password = h("input", {
    id: "lab-password", name: "password", type: "password", autocomplete: "current-password",
    maxlength: "1024", required: "",
  });
  const submit = h("button", { type: "submit" }, "Sign in");
  const captchaBox = h("div", { class: "captcha" });
  const form = h("form", { class: "auth-form", novalidate: "" },
    h("label", { for: "lab-username" }, "Username"),
    username,
    h("p", { id: "lab-username-hint", class: "hint" },
      "Letters, numbers, dots, underscores or hyphens. Usernames are lowercased; email login is not supported."),
    h("label", { for: "lab-password" }, "Password"),
    password,
    forgotUrl ? h("p", { class: "forgot-row" },
      h("button", { type: "button", class: "link-button", "data-action": "show-forgot" }, "Forgot your password?")) : null,
    captchaBox,
    errorBox,
    submit,
  );

  const forgotUsername = h("input", {
    id: "lab-forgot-username", name: "username", autocomplete: "username", autocapitalize: "none",
    spellcheck: "false", maxlength: "128", required: "",
  });
  const forgotSubmit = h("button", { type: "submit" }, "Send reset link");
  const forgotStatus = h("div", { "aria-live": "polite", "aria-atomic": "true" });
  const forgotForm = h("form", { class: "auth-form", novalidate: "" },
    h("label", { for: "lab-forgot-username" }, "Username"),
    forgotUsername,
    h("p", { class: "hint" }, "Auth0 emails a reset link to the address saved on your account."),
    forgotStatus,
    forgotSubmit,
  );
  const backButton = () => h("button", { type: "button", class: "link-button", "data-action": "show-login" }, "Back to sign in");

  const loginView = h("div", {},
    h("p", { class: "eyebrow" }, "WELCOME BACK"),
    h("h2", { id: "lab-login-title" }, "Sign in to the lab"),
    h("p", { class: "muted" }, "One account from either database is all you need."),
    form,
    signupUrl ? h("p", { class: "footnote" }, "New to the lab? ", h("a", { href: signupUrl }, "Create an account")) : null,
    h("p", { class: "footnote" }, "Sign in with your username, not email.", h("br"),
      "New accounts may take time to appear in Auth0 search."),
  );
  const forgotView = h("div", { hidden: "" },
    h("p", { class: "eyebrow" }, "ACCOUNT RECOVERY"),
    h("h2", { id: "lab-forgot-title", tabindex: "-1" }, "Forgot your password?"),
    h("p", { class: "muted" }, "Enter your username. The lab app finds your database and asks Auth0 to email you a reset link."),
    forgotForm,
    h("p", { class: "footnote" }, backButton()),
  );
  const sentView = h("div", { hidden: "" },
    h("p", { class: "eyebrow success" }, "CHECK YOUR EMAIL"),
    h("h2", { id: "lab-sent-title", tabindex: "-1" }, "Reset link requested"),
    h("p", { class: "muted", role: "status" }, messages.resetSent),
    h("p", { class: "footnote" }, "The link opens an Auth0 page where you choose a new password. It can be used once.", h("br"),
      "Didn't get it? Wait a few minutes before requesting again."),
    h("p", { class: "footnote" }, backButton()),
  );

  const hint = options.auth0Config.extraParams?.login_hint;
  if (typeof hint === "string" && normalizeUsername(hint)) username.value = normalizeUsername(hint) as string;

  root.replaceChildren(h("div", { class: "lab-hosted" },
    h("main", { class: "shell" },
      h("header", { class: "brand" },
        h("span", { class: "brand-icon", "aria-hidden": "true" }, "2"), " AUTH0 / CONNECTION LAB"),
      h("div", { class: "login-grid" },
        h("section", { class: "intro" },
          h("p", { class: "eyebrow" }, "TWO DIRECTORIES. ONE APPLICATION."),
          h("h1", {}, "Different databases.", h("br"), h("span", {}, "Same front door.")),
          h("p", { class: "lead" },
            "Sign in with your developer or ecommerce username. The server finds the right database automatically."),
          h("div", { class: "connections", "aria-label": "Configured database connections" },
            ...connections.map((name) => h("span", {}, h("i", { "aria-hidden": "true" }), name))),
          h("ol", { class: "flow" },
            h("li", {}, h("strong", {}, "Find the account"), h("span", {}, "The lab app searches the Auth0 Management API.")),
            h("li", {}, h("strong", {}, "Resolve its connection"), h("span", {}, "No database selector. No guessing.")),
            h("li", {}, h("strong", {}, "Authenticate on Auth0"), h("span", {}, "Hosted login, then back to your application.")),
          ),
        ),
        h("section", { class: "card", "aria-label": "Sign in" }, loginView,
          forgotUrl ? forgotView : null, forgotUrl ? sentView : null),
      ),
      h("footer", {}, "Hosted by Auth0", h("span", {}, "Custom Login Page / auth0.js")),
    ),
  ));

  let webAuth: WebAuthLike | undefined;
  let captcha: Captcha | undefined;
  try {
    webAuth = options.webAuth ?? createWebAuth(options.auth0Config);
    captcha = webAuth.renderCaptcha?.(captchaBox);
  } catch {
    console.error("[lab-hosted-login] auth0.js setup failed");
  }

  const showError = (message: string) => {
    const box = h("p", { class: "error", role: "alert" }, message);
    errorBox.replaceChildren(box);
  };
  const setPending = (pending: boolean) => {
    username.disabled = pending;
    password.disabled = pending;
    submit.disabled = pending;
    submit.textContent = pending ? "Signing in..." : "Sign in";
    form.setAttribute("aria-busy", String(pending));
  };
  const fail = (message: string) => {
    password.value = "";
    captcha?.reload();
    setPending(false);
    showError(message);
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    errorBox.replaceChildren();
    const name = normalizeUsername(username.value);
    if (!name) return showError(messages.invalidUsername);
    if (!password.value) return showError(messages.missingPassword);
    if (!webAuth) return showError(messages.setup);

    setPending(true);
    const resolved = await resolveConnection(name, options.resolveUrl, connections, fetcher);
    if (!resolved.ok) {
      return fail(resolved.reason === "not_found" ? messages.credentials
        : resolved.reason === "rate_limited" ? messages.rateLimited : messages.unavailable);
    }
    try {
      // On success auth0.js redirects back to the application; the callback runs only on failure.
      webAuth.login({
        realm: resolved.connection,
        username: name,
        password: password.value,
        captcha: captcha?.getValue(),
      }, (error) => fail(auth0ErrorMessage(error)));
    } catch {
      fail(messages.generic);
    }
  });

  const showView = (view: "login" | "forgot" | "sent") => {
    loginView.hidden = view !== "login";
    forgotView.hidden = view !== "forgot";
    sentView.hidden = view !== "sent";
    const focusTarget = view === "login" ? username : view === "forgot" ? forgotUsername
      : sentView.querySelector<HTMLElement>("#lab-sent-title");
    focusTarget?.focus();
  };
  root.addEventListener("click", (event) => {
    const action = (event.target as HTMLElement | null)?.closest?.("[data-action]")?.getAttribute("data-action");
    if (action === "show-forgot") {
      forgotStatus.replaceChildren();
      forgotUsername.value = normalizeUsername(username.value) ?? "";
      showView("forgot");
    } else if (action === "show-login") {
      showView("login");
    }
  });

  forgotForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (forgotSubmit.disabled || !forgotUrl) return;
    forgotStatus.replaceChildren();
    const name = normalizeUsername(forgotUsername.value);
    if (!name) {
      forgotStatus.replaceChildren(h("p", { class: "error", role: "alert" }, messages.invalidUsername));
      return;
    }
    forgotSubmit.disabled = true;
    forgotUsername.disabled = true;
    forgotSubmit.textContent = "Sending...";
    const result = await requestPasswordReset(name, forgotUrl, fetcher);
    forgotSubmit.disabled = false;
    forgotUsername.disabled = false;
    forgotSubmit.textContent = "Send reset link";
    if (result.ok) {
      showView("sent");
      return;
    }
    forgotStatus.replaceChildren(h("p", { class: "error", role: "alert" },
      result.reason === "rate_limited" ? messages.resetRateLimited : messages.resetUnavailable));
  });

  return { form, username, password, submit, forgotForm, forgotUsername, forgotSubmit, showView };
}
