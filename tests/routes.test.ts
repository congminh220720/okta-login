import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError, SignupError } from "@/lib/auth0";

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  signup: vi.fn(),
  sameOrigin: vi.fn(),
  allowLogin: vi.fn(),
  allowSignup: vi.fn(),
  session: { user: undefined as unknown, save: vi.fn(), destroy: vi.fn() },
}));
vi.mock("@/lib/auth0", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/auth0")>(),
  authenticate: mocks.authenticate,
  signup: mocks.signup,
}));
vi.mock("@/lib/http", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/http")>(),
  sameOrigin: mocks.sameOrigin,
}));
vi.mock("@/lib/config", () => ({
  getConfig: () => ({ AUTH0_DEV_CONNECTION: "devdb", AUTH0_ECOM_CONNECTION: "ecomdb" }),
}));
vi.mock("@/lib/rate-limit", () => ({ allowLogin: mocks.allowLogin, allowSignup: mocks.allowSignup }));
vi.mock("@/lib/session", () => ({ getSession: async () => mocks.session }));

import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { POST as signup } from "@/app/api/auth/signup/route";

function request(body: unknown = { identifier: "devuser", password: "password" }) {
  return new Request("http://localhost:3000/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "http://localhost:3000" },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  mocks.sameOrigin.mockReturnValue(true);
  mocks.allowLogin.mockReturnValue(true);
  mocks.allowSignup.mockReturnValue(true);
  mocks.signup.mockResolvedValue(undefined);
  mocks.session.user = undefined;
  mocks.session.save.mockResolvedValue(undefined);
  mocks.authenticate.mockResolvedValue({ sub: "auth0|123", connection: "devdb", expiresAt: 123456789 });
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("login route", () => {
  it("saves session and returns no profile/token to browser", async () => {
    const response = await login(request());
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ ok: true });
    expect(mocks.session.save).toHaveBeenCalledOnce();
    expect(mocks.session.user).toMatchObject({ connection: "devdb" });
  });
  it("rejects cross-origin before calling Auth0", async () => {
    mocks.sameOrigin.mockReturnValue(false);
    expect((await login(request())).status).toBe(403);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });
  it("rejects invalid input before calling Auth0", async () => {
    expect((await login(request({ identifier: "dev", password: "" }))).status).toBe(400);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });
  it("rejects email login and client-selected login connections", async () => {
    expect((await login(request({ identifier: "dev@example.com", password: "password" }))).status).toBe(400);
    expect((await login(request({ identifier: "dev", password: "password", connection: "devdb" }))).status).toBe(400);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });
  it("normalizes a username before searching Auth0", async () => {
    await login(request({ identifier: " Dev.User ", password: " password " }));
    expect(mocks.authenticate).toHaveBeenCalledWith("dev.user", " password ");
  });
  it("enforces rate limit before Auth0", async () => {
    mocks.allowLogin.mockReturnValue(false);
    expect((await login(request())).status).toBe(429);
    expect(mocks.authenticate).not.toHaveBeenCalled();
  });

  describe("signup route", () => {
    const body = { username: " New.User ", email: " New.User@Example.com ", password: " password ", connection: "ecomdb" };
    it("creates an account without email or a login session", async () => {
      const response = await signup(request(body));
      expect(response.status).toBe(201);
      expect(await response.json()).toEqual({ ok: true });
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(mocks.signup).toHaveBeenCalledWith("new.user", " password ", "ecomdb", "new.user@example.com");
      expect(mocks.authenticate).not.toHaveBeenCalled();
      expect(mocks.session.save).not.toHaveBeenCalled();
    });
    it.each([
      { ...body, connection: "otherdb" },
      { ...body, username: "dev@example.com" },
      { ...body, password: "short" },
      { ...body, email: "not-an-email" },
      { ...body, email: undefined },
      { ...body, app_metadata: { admin: true } },
    ])("rejects invalid signup input before Auth0", async (input) => {
      expect((await signup(request(input))).status).toBe(400);
      expect(mocks.signup).not.toHaveBeenCalled();
    });
    it("rejects CSRF before creating a user", async () => {
      mocks.sameOrigin.mockReturnValue(false);
      expect((await signup(request(body))).status).toBe(403);
      expect(mocks.signup).not.toHaveBeenCalled();
    });
    it("rate limits signup independently of login", async () => {
      mocks.allowSignup.mockReturnValue(false);
      expect((await signup(request(body))).status).toBe(429);
      expect(mocks.signup).not.toHaveBeenCalled();
    });
    it.each([
      new SignupError("username_unavailable", 409),
      new SignupError("signup_rejected", 400),
      new SignupError("email_required", 400),
      new SignupError("username_not_enabled", 400),
      new SignupError("password_policy", 400),
      new AuthError("provider_unavailable", 503),
    ])("reports $code instead of success", async (error) => {
      mocks.signup.mockRejectedValue(error);
      expect((await signup(request(body))).status).toBe(error.status);
      expect(mocks.session.save).not.toHaveBeenCalled();
    });
    it("returns an actionable email-required message and stable code", async () => {
      mocks.signup.mockRejectedValue(new SignupError("email_required", 400));
      const response = await signup(request(body));
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        code: "email_required",
        error: expect.stringContaining("Auth0 requires an email"),
      });
    });
  });
  it.each([
    new AuthError("invalid_credentials", 401),
    new AuthError("provider_unavailable", 503),
    new AuthError("mfa_required", 403),
  ])("does not save a session on $code", async (error) => {
    mocks.authenticate.mockRejectedValue(error);
    expect((await login(request())).status).toBe(error.status);
    expect(mocks.session.save).not.toHaveBeenCalled();
  });
  it("reports session persistence failures instead of success", async () => {
    mocks.session.save.mockRejectedValue(new Error("storage error"));
    expect((await login(request())).status).toBe(500);
  });
});

describe("logout route", () => {
  it("destroys the app cookie", async () => {
    expect((await logout(request())).status).toBe(200);
    expect(mocks.session.destroy).toHaveBeenCalledOnce();
  });
  it("rejects cross-origin without destroying the session", async () => {
    mocks.sameOrigin.mockReturnValue(false);
    expect((await logout(request())).status).toBe(403);
    expect(mocks.session.destroy).not.toHaveBeenCalled();
  });
});
