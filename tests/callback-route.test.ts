import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError } from "@/lib/auth0";

const mocks = vi.hoisted(() => ({
  exchangeCode: vi.fn(),
  connectionForUser: vi.fn(),
  tx: { transaction: undefined as unknown, save: vi.fn(), destroy: vi.fn() },
  session: { user: undefined as unknown, accessToken: undefined as unknown, accessTokenExpiresAt: undefined as unknown, save: vi.fn() },
}));
const config = {
  AUTH0_DOMAIN: "lab.example.com", AUTH0_CLIENT_ID: "web-client", AUTH0_CLIENT_SECRET: "web-secret",
  APP_ORIGIN: "http://localhost:5173", AUTH0_DEV_CONNECTION: "devdb", AUTH0_ECOM_CONNECTION: "ecomdb",
};
vi.mock("@/lib/config", () => ({ getConfig: () => config }));
vi.mock("@/lib/auth0", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/auth0")>(),
  connectionForUser: mocks.connectionForUser,
}));
vi.mock("@/lib/oidc", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/oidc")>(),
  createOidcClient: () => ({ exchangeCode: mocks.exchangeCode }),
}));
vi.mock("@/lib/session", () => ({
  getSession: async () => mocks.session,
  getTransactionSession: async () => mocks.tx,
  TRANSACTION_MAX_AGE_MS: 600_000,
}));

import { GET as login } from "@/app/auth/login/route";
import { GET as callback } from "@/app/auth/callback/route";

const transaction = { state: "state-1", nonce: "nonce-1", codeVerifier: "verifier-1", createdAt: Date.now() };
const callbackRequest = (query: string) => new Request(`http://localhost:5173/auth/callback?${query}`);
const location = (response: Response) => response.headers.get("location");

beforeEach(() => {
  mocks.tx.transaction = { ...transaction, createdAt: Date.now() };
  mocks.session.user = undefined;
  mocks.session.accessToken = undefined;
  mocks.exchangeCode.mockResolvedValue({
    sub: "auth0|abc", name: "Lab User", accessToken: "access-token-value",
    accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 86400,
    idTokenExpiresAt: Math.floor(Date.now() / 1000) + 36000,
  });
  mocks.connectionForUser.mockResolvedValue({ connection: "ecomdb", username: "labuser" });
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("GET /auth/login", () => {
  it("stores a transaction and redirects to Auth0 /authorize", async () => {
    mocks.tx.transaction = undefined;
    const response = await login();
    expect(response.status).toBe(302);
    const url = new URL(location(response) ?? "");
    expect(url.origin + url.pathname).toBe("https://lab.example.com/authorize");
    const saved = mocks.tx.transaction as typeof transaction;
    expect(url.searchParams.get("state")).toBe(saved.state);
    expect(url.searchParams.get("nonce")).toBe(saved.nonce);
    expect(mocks.tx.save).toHaveBeenCalledOnce();
  });
});

describe("GET /auth/callback", () => {
  it("exchanges the code, stores user + token in the session and goes home", async () => {
    const response = await callback(callbackRequest("code=abc&state=state-1"));
    expect(location(response)).toBe("http://localhost:5173/home");
    expect(mocks.exchangeCode).toHaveBeenCalledWith("abc", expect.objectContaining({ state: "state-1" }));
    expect(mocks.connectionForUser).toHaveBeenCalledWith("auth0|abc");
    expect(mocks.session.user).toMatchObject({
      sub: "auth0|abc", connection: "ecomdb", username: "labuser", method: "universal-login",
    });
    expect(mocks.session.accessToken).toBe("access-token-value");
    const user = mocks.session.user as { expiresAt: number };
    expect(user.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 3600);
    expect(mocks.tx.destroy).toHaveBeenCalled();
  });

  it.each([
    ["mismatched state", "code=abc&state=attacker"],
    ["missing state", "code=abc"],
    ["missing code", "state=state-1"],
  ])("rejects %s without exchanging the code", async (_label, query) => {
    const response = await callback(callbackRequest(query));
    expect(location(response)).toBe("http://localhost:5173/?error=state");
    expect(mocks.exchangeCode).not.toHaveBeenCalled();
    expect(mocks.session.save).not.toHaveBeenCalled();
  });

  it("rejects a callback with no stored transaction (replay / other browser)", async () => {
    mocks.tx.transaction = undefined;
    expect(location(await callback(callbackRequest("code=abc&state=state-1")))).toBe("http://localhost:5173/?error=state");
  });

  it("rejects an expired transaction", async () => {
    mocks.tx.transaction = { ...transaction, createdAt: Date.now() - 700_000 };
    expect(location(await callback(callbackRequest("code=abc&state=state-1")))).toBe("http://localhost:5173/?error=state");
  });

  it.each([["access_denied", "denied"], ["login_required", "auth0"], ["<script>", "auth0"]])(
    "handles Auth0 error=%s", async (error, mapped) => {
      const response = await callback(callbackRequest(`error=${encodeURIComponent(error)}&state=state-1`));
      expect(location(response)).toBe(`http://localhost:5173/?error=${mapped}`);
      expect(mocks.exchangeCode).not.toHaveBeenCalled();
    },
  );

  it("does not create a session for users outside devdb/ecomdb", async () => {
    mocks.connectionForUser.mockRejectedValue(new AuthError("invalid_credentials", 401));
    expect(location(await callback(callbackRequest("code=abc&state=state-1")))).toBe("http://localhost:5173/?error=denied");
    expect(mocks.session.save).not.toHaveBeenCalled();
  });

  it("does not create a session when the exchange fails", async () => {
    mocks.exchangeCode.mockRejectedValue(new AuthError("provider_unavailable", 503));
    expect(location(await callback(callbackRequest("code=abc&state=state-1")))).toBe("http://localhost:5173/?error=auth0");
    expect(mocks.session.save).not.toHaveBeenCalled();
  });
});
