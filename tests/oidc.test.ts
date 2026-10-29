import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { authorizeUrl, createOidcClient, createTransaction, logoutUrl, type Transaction } from "@/lib/oidc";
import type { Config } from "@/lib/config";

const config: Config = {
  AUTH0_DOMAIN: "lab.example.com",
  AUTH0_CLIENT_ID: "web-client",
  AUTH0_CLIENT_SECRET: "web-secret",
  AUTH0_MANAGEMENT_CLIENT_ID: "m2m-client",
  AUTH0_MANAGEMENT_CLIENT_SECRET: "m2m-secret",
  AUTH0_DEV_CONNECTION: "devdb",
  AUTH0_ECOM_CONNECTION: "ecomdb",
  SESSION_SECRET: "test-only-secret-that-is-at-least-32-characters",
  APP_ORIGIN: "http://localhost:5173",
};

let keys: Awaited<ReturnType<typeof generateKeyPair>>;
let jwks: { keys: object[] };
let transaction: Transaction;

beforeAll(async () => {
  keys = await generateKeyPair("RS256");
  jwks = { keys: [{ ...await exportJWK(keys.publicKey), kid: "k1", alg: "RS256", use: "sig" }] };
});
beforeEach(() => {
  transaction = createTransaction();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

async function idToken(overrides: Record<string, unknown> = {}, wrongKey = false) {
  const key = wrongKey ? (await generateKeyPair("RS256")).privateKey : keys.privateKey;
  return new SignJWT({
    sub: "auth0|abc", name: "Lab User", nonce: transaction.nonce,
    iss: "https://lab.example.com/", aud: "web-client",
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  }).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(key);
}

function exchange(tokenResponse: Response) {
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(tokenResponse)
    .mockResolvedValueOnce(Response.json(jwks));
  return { fetcher, run: () => createOidcClient(config, fetcher).exchangeCode("auth-code", transaction) };
}

const tokenBody = async (overrides: Record<string, unknown> = {}) => ({
  access_token: "access-token-value", id_token: await idToken(), expires_in: 86400, token_type: "Bearer",
  ...overrides,
});

describe("authorize URL", () => {
  it("requests a code with PKCE S256, state, nonce and the app callback", () => {
    const url = new URL(authorizeUrl(config, transaction));
    expect(url.origin + url.pathname).toBe("https://lab.example.com/authorize");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: "code",
      client_id: "web-client",
      redirect_uri: "http://localhost:5173/auth/callback",
      scope: "openid profile",
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: createHash("sha256").update(transaction.codeVerifier).digest("base64url"),
      code_challenge_method: "S256",
    });
    expect(url.toString()).not.toContain("web-secret");
    expect(url.toString()).not.toContain(transaction.codeVerifier);
  });

  it("creates unpredictable transactions", () => {
    const other = createTransaction();
    expect(other.state).not.toBe(transaction.state);
    expect(transaction.codeVerifier.length).toBeGreaterThanOrEqual(43);
  });

  it("builds an Auth0 logout URL returning to the app", () => {
    const url = new URL(logoutUrl(config));
    expect(url.pathname).toBe("/v2/logout");
    expect(url.searchParams.get("returnTo")).toBe("http://localhost:5173");
    expect(url.searchParams.get("client_id")).toBe("web-client");
  });
});

describe("code exchange", () => {
  it("exchanges the code with secret + verifier and verifies the ID token", async () => {
    const { fetcher, run } = exchange(Response.json(await tokenBody()));
    const result = await run();
    expect(result).toMatchObject({ sub: "auth0|abc", name: "Lab User", accessToken: "access-token-value" });
    const body = JSON.parse(String(fetcher.mock.calls[0][1]?.body));
    expect(body).toEqual({
      grant_type: "authorization_code", client_id: "web-client", client_secret: "web-secret",
      code: "auth-code", code_verifier: transaction.codeVerifier,
      redirect_uri: "http://localhost:5173/auth/callback",
    });
  });

  it.each([
    ["wrong nonce", { nonce: "replayed" }],
    ["missing nonce", { nonce: undefined }],
    ["wrong issuer", { iss: "https://evil.example.com/" }],
    ["wrong audience", { aud: "other-client" }],
    ["expired", { exp: 1 }],
    ["wrong azp", { azp: "other-client" }],
  ])("rejects an ID token with %s", async (_label, claims) => {
    const { run } = exchange(Response.json(await tokenBody({ id_token: await idToken(claims) })));
    await expect(run()).rejects.toMatchObject({ status: 503 });
  });

  it("rejects a forged ID token signature", async () => {
    const { run } = exchange(Response.json(await tokenBody({ id_token: await idToken({}, true) })));
    await expect(run()).rejects.toMatchObject({ status: 503 });
  });

  it("maps invalid_grant (reused/expired code) to a retryable login error", async () => {
    const { run } = exchange(Response.json({ error: "invalid_grant", error_description: "secret detail" }, { status: 403 }));
    await expect(run()).rejects.toMatchObject({ code: "invalid_credentials", status: 401 });
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("secret detail");
  });

  it.each([
    [Response.json({ error: "unauthorized_client" }, { status: 403 })],
    [Response.json({ access_token: "x", expires_in: 10, token_type: "Bearer" })],
  ])("treats other token failures as provider errors (%#)", async (response) => {
    const { run } = exchange(response);
    await expect(run()).rejects.toMatchObject({ status: 503 });
  });

  it("handles network failure", async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error("down"));
    await expect(createOidcClient(config, fetcher).exchangeCode("c", transaction)).rejects.toMatchObject({ status: 503 });
  });
});

describe("userinfo", () => {
  it("calls /userinfo with the bearer token", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ sub: "auth0|abc" }));
    await expect(createOidcClient(config, fetcher).userInfo("tok")).resolves.toEqual({ sub: "auth0|abc" });
    expect(String(fetcher.mock.calls[0][0])).toBe("https://lab.example.com/userinfo");
    expect(fetcher.mock.calls[0][1]?.headers).toEqual({ Authorization: "Bearer tok" });
  });
  it.each([[401, 401], [500, 503]])("maps HTTP %s", async (status, expected) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status }));
    await expect(createOidcClient(config, fetcher).userInfo("tok")).rejects.toMatchObject({ status: expected });
  });
});
