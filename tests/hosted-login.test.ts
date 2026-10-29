// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  auth0ErrorMessage, createWebAuth, messages, mount, normalizeUsername, resolveConnection,
  type Auth0LoginError, type WebAuthLike,
} from "../hosted-pages/src/login";

const auth0Config = {
  auth0Domain: "lab.example.com",
  clientID: "web-client",
  callbackURL: "http://localhost:5173/callback",
  auth0Tenant: "lab",
  authorizationServer: { issuer: "https://lab.example.com/" },
  internalOptions: { state: "state-123", leeway: "30", _csrf: "csrf-token" },
};
const resolveUrl = "http://localhost:5173/api/auth/resolve-connection";
const forgotPasswordUrl = "http://localhost:5173/api/auth/forgot-password";

function setup(fetchResponse: Response | Error = Response.json({ connection: "ecomdb" })) {
  const login = vi.fn<WebAuthLike["login"]>();
  const captcha = { getValue: vi.fn(() => "captcha-answer"), reload: vi.fn() };
  const webAuth: WebAuthLike = { login, renderCaptcha: vi.fn(() => captcha) };
  const fetcher = vi.fn<typeof fetch>(async () => {
    if (fetchResponse instanceof Error) throw fetchResponse;
    return fetchResponse;
  });
  const root = document.createElement("div");
  document.body.replaceChildren(root);
  const ui = mount(root, {
    auth0Config, resolveUrl, connections: ["devdb", "ecomdb"],
    signupUrl: "http://localhost:5173/signup", forgotPasswordUrl, webAuth, fetch: fetcher,
  });
  const submit = async (username: string, password: string) => {
    ui.username.value = username;
    ui.password.value = password;
    ui.form.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(fetcher.mock.calls.length + root.querySelectorAll("[role=alert]").length).toBeGreaterThan(0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  };
  return { root, ui, login, captcha, fetcher, submit };
}

const alertText = (root: HTMLElement) => root.querySelector("[role=alert]")?.textContent;

beforeEach(() => {
  document.head.replaceChildren();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("hosted login UI", () => {
  it("renders the lab login layout with scoped styles and no ONE branding", () => {
    const { root } = setup();
    expect(root.textContent).toContain("Sign in to the lab");
    expect(root.textContent).toContain("Same front door.");
    expect([...root.querySelectorAll(".connections span")].map((el) => el.textContent)).toEqual(["devdb", "ecomdb"]);
    expect(root.querySelector("a")?.getAttribute("href")).toBe("http://localhost:5173/signup");
    expect(document.getElementById("lab-hosted-styles")?.textContent).toContain(".lab-hosted");
    expect(root.innerHTML).not.toMatch(/Your Number ONE|Ocean Network|one-line|BD0F72/i);
    expect(root.querySelector("label[for=lab-username]")?.textContent).toBe("Username");
  });

  it("resolves the connection then logs in to that realm with the captcha answer", async () => {
    const { login, fetcher, submit } = setup();
    await submit(" Dev.User ", " secret ");
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe(resolveUrl);
    expect(init).toMatchObject({ method: "POST", mode: "cors", credentials: "omit" });
    expect(JSON.parse(String(init?.body))).toEqual({ username: "dev.user" });
    expect(login).toHaveBeenCalledWith(
      { realm: "ecomdb", username: "dev.user", password: " secret ", captcha: "captcha-answer" },
      expect.any(Function),
    );
  });

  it.each([
    ["dev@example.com", "x", messages.invalidUsername],
    ["dev", "", messages.missingPassword],
  ])("validates %s before calling the lab app", async (username, password, message) => {
    const { root, fetcher, login, submit } = setup();
    await submit(username, password);
    expect(alertText(root)).toBe(message);
    expect(fetcher).not.toHaveBeenCalled();
    expect(login).not.toHaveBeenCalled();
  });

  it.each([
    [new Response(null, { status: 404 }), messages.credentials],
    [new Response(null, { status: 429 }), messages.rateLimited],
    [new Response(null, { status: 503 }), messages.unavailable],
    [new TypeError("Failed to fetch"), messages.unavailable],
    [Response.json({ connection: "otherdb" }), messages.unavailable],
  ])("never calls Auth0 when lookup fails (%#)", async (response, message) => {
    const { root, login, captcha, ui, submit } = setup(response);
    await submit("devuser", "secret");
    expect(alertText(root)).toBe(message);
    expect(login).not.toHaveBeenCalled();
    expect(ui.password.value).toBe("");
    expect(ui.submit.disabled).toBe(false);
    expect(captcha.reload).toHaveBeenCalled();
  });

  it("shows a safe error, clears the password and re-enables the form when Auth0 rejects", async () => {
    const { root, login, ui, captcha, submit } = setup();
    login.mockImplementation((_options, callback) => callback({
      code: "access_denied", description: "Wrong username or password. secret-detail",
    }));
    await submit("devuser", "secret");
    expect(alertText(root)).toBe(messages.credentials);
    expect(root.innerHTML).not.toContain("secret-detail");
    expect(ui.password.value).toBe("");
    expect(ui.submit.disabled).toBe(false);
    expect(captcha.reload).toHaveBeenCalled();
  });

  it("prevents duplicate submissions while pending", async () => {
    const { ui, fetcher } = setup();
    let release!: (value: Response) => void;
    fetcher.mockImplementation(() => new Promise((resolve) => { release = resolve; }));
    ui.username.value = "devuser";
    ui.password.value = "secret";
    ui.form.dispatchEvent(new Event("submit", { cancelable: true }));
    ui.form.dispatchEvent(new Event("submit", { cancelable: true }));
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(ui.submit.textContent).toBe("Signing in...");
    release(Response.json({ connection: "devdb" }));
  });

  it("renders text content safely and drops non-http signup URLs", () => {
    const root = document.createElement("div");
    mount(root, {
      auth0Config, resolveUrl, webAuth: { login: vi.fn() },
      connections: ["<img src=x onerror=alert(1)>"], signupUrl: "javascript:alert(1)",
    });
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("a")).toBeNull();
  });

  it("shows a setup error instead of failing silently when auth0.js is missing", async () => {
    const root = document.createElement("div");
    const fetcher = vi.fn<typeof fetch>();
    const ui = mount(root, { auth0Config, resolveUrl, fetch: fetcher });
    ui.username.value = "devuser";
    ui.password.value = "secret";
    ui.form.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(alertText(root)).toBe(messages.setup));
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("hosted forgot password", () => {
  const click = (root: HTMLElement, text: string) => {
    const button = [...root.querySelectorAll("button")].find((el) => el.textContent === text && !el.closest("[hidden]"));
    if (!button) throw new Error(`Visible button not found: ${text}`);
    button.click();
  };
  const visible = (root: HTMLElement, text: string) =>
    [...root.querySelectorAll("h2")].some((el) => el.textContent === text && !el.closest("[hidden]"));

  it("switches to the forgot view, prefilled with the typed username, and back", () => {
    const { root, ui } = setup();
    ui.username.value = " Dev.User ";
    click(root, "Forgot your password?");
    expect(visible(root, "Forgot your password?")).toBe(true);
    expect(visible(root, "Sign in to the lab")).toBe(false);
    expect(ui.forgotUsername.value).toBe("dev.user");
    expect(document.activeElement).toBe(ui.forgotUsername);
    click(root, "Back to sign in");
    expect(visible(root, "Sign in to the lab")).toBe(true);
  });

  it("posts only the username and shows the same confirmation for any account", async () => {
    const { root, ui, fetcher, login } = setup(Response.json({ ok: true }));
    ui.showView("forgot");
    ui.forgotUsername.value = "devuser";
    ui.forgotForm.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(visible(root, "Reset link requested")).toBe(true));
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe(forgotPasswordUrl);
    expect(init).toMatchObject({ method: "POST", mode: "cors", credentials: "omit" });
    expect(JSON.parse(String(init?.body))).toEqual({ username: "devuser" });
    expect(root.textContent).toContain(messages.resetSent);
    expect(login).not.toHaveBeenCalled();
  });

  it.each([
    [new Response(null, { status: 429 }), messages.resetRateLimited],
    [new Response(null, { status: 503 }), messages.resetUnavailable],
    [new TypeError("Failed to fetch"), messages.resetUnavailable],
  ])("shows an error and stays on the form when the request fails (%#)", async (response, message) => {
    const { root, ui } = setup(response);
    ui.showView("forgot");
    ui.forgotUsername.value = "devuser";
    ui.forgotForm.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(root.querySelector("[role=alert]")?.textContent).toBe(message));
    expect(visible(root, "Forgot your password?")).toBe(true);
    expect(ui.forgotSubmit.disabled).toBe(false);
  });

  it("validates the username before sending", async () => {
    const { root, ui, fetcher } = setup();
    ui.showView("forgot");
    ui.forgotUsername.value = "dev@example.com";
    ui.forgotForm.dispatchEvent(new Event("submit", { cancelable: true }));
    expect(root.querySelector("[role=alert]")?.textContent).toBe(messages.invalidUsername);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("hides the link when no forgot-password URL is configured", () => {
    const root = document.createElement("div");
    mount(root, { auth0Config, resolveUrl, webAuth: { login: vi.fn() } });
    expect(root.textContent).not.toContain("Forgot your password?");
  });
});

describe("hosted login helpers", () => {
  it("normalizes usernames like the server", () => {
    expect(normalizeUsername(" Dev.User ")).toBe("dev.user");
    expect(normalizeUsername("dev@example.com")).toBeUndefined();
    expect(normalizeUsername("a".repeat(129))).toBeUndefined();
  });

  it.each<[Auth0LoginError, string]>([
    [{ code: "access_denied" }, messages.credentials],
    [{ error: "invalid_user_password" }, messages.credentials],
    [{ code: "too_many_attempts" }, messages.blocked],
    [{ code: "invalid_captcha" }, messages.captcha],
    [{ code: "password_leaked" }, messages.leaked],
    [{ code: "something_new" }, messages.generic],
    [null, messages.generic],
  ])("maps Auth0 error %j", (error, message) => {
    expect(auth0ErrorMessage(error)).toBe(message);
  });

  it("rejects resolve responses with malformed JSON", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response("not json", { status: 200 }));
    await expect(resolveConnection("devuser", resolveUrl, ["devdb"], fetcher))
      .resolves.toEqual({ ok: false, reason: "unavailable" });
  });

  it("builds WebAuth from the Auth0 page config like the default template", () => {
    const WebAuth = vi.fn(function (this: object, params: object) { Object.assign(this, { params }); });
    (globalThis as { auth0?: unknown }).auth0 = { WebAuth };
    try {
      createWebAuth(auth0Config);
      expect(WebAuth).toHaveBeenCalledWith({
        overrides: { __tenant: "lab", __token_issuer: "https://lab.example.com/" },
        domain: "lab.example.com",
        clientID: "web-client",
        redirectUri: "http://localhost:5173/callback",
        responseType: "code",
        state: "state-123",
        leeway: 30,
        _csrf: "csrf-token",
      });
    } finally {
      delete (globalThis as { auth0?: unknown }).auth0;
    }
  });
});
