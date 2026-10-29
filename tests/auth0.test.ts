import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createAuth0Client } from "@/lib/auth0";
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
  APP_ORIGIN: "http://localhost:3000",
};
const profile = (connection = "devdb", identifier = "devuser") => ({
  user_id: "auth0|123",
  username: identifier,
  identities: [{ provider: "auth0", connection }],
});
const identity = () => ({
  sub: "auth0|123",
  name: "Lab User",
  exp: Math.floor(Date.now() / 1000) + 7200,
});
const managementResponse = () => Response.json({
  access_token: "management-token",
  expires_in: 3600,
  token_type: "Bearer",
});

function fixture(users: unknown = [profile()], login = Response.json({ id_token: "id-token" })) {
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(managementResponse())
    .mockResolvedValueOnce(Response.json(users))
    .mockResolvedValueOnce(login);
  const verify = vi.fn().mockResolvedValue(identity());
  return { fetcher, verify, client: createAuth0Client(config, fetcher, verify) };
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("Management lookup -> password realm", () => {
  it.each(["devdb", "ecomdb"])("authenticates the resolved %s connection", async (connection) => {
    const { client, fetcher } = fixture([profile(connection)]);
    const user = await client.authenticate("devuser", " password ");
    expect(user.connection).toBe(connection);
    expect(user.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 3600);
    expect(String(fetcher.mock.calls[1][0])).toContain("/api/v2/users?");
    expect(user.username).toBe("devuser");
    const request = JSON.parse(String(fetcher.mock.calls[2][1]?.body));
    expect(request).toMatchObject({
      grant_type: "http://auth0.com/oauth/grant-type/password-realm",
      realm: connection,
      username: "devuser",
      password: " password ",
      client_id: "web-client",
      scope: "openid profile",
    });
    expect(fetcher.mock.calls[1][1]?.headers).toEqual({ Authorization: "Bearer management-token" });
    expect(user).not.toHaveProperty("id_token");
    expect(user).not.toHaveProperty("password");
  });

  it.each([
    ["missing user", []],
    ["other connection", [profile("otherdb")]],
    ["duplicate accounts", [profile("devdb"), profile("ecomdb")]],
    ["wrong exact username", [profile("devdb", "otheruser")]],
    ["email-only profile", [{ ...profile(), username: undefined, email: "devuser@example.com" }]],
    ["social identity", [{ ...profile(), identities: [{ provider: "google-oauth2", connection: "devdb" }] }]],
    ["linked identities", [{ ...profile(), identities: [...profile().identities, ...profile("ecomdb").identities] }]],
  ])("does not call login for %s", async (_label, users) => {
    const { client, fetcher } = fixture(users);
    await expect(client.authenticate("devuser", "wrong")).rejects.toMatchObject({
      code: "invalid_credentials", status: 401,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("escapes username search syntax and still requires exact username", async () => {
    const username = 'dev" or username:*';
    const { client, fetcher } = fixture([profile("devdb", username)]);
    await client.authenticate(username, "password");
    const url = new URL(String(fetcher.mock.calls[1][0]));
    expect(url.pathname).toBe("/api/v2/users");
    expect(url.searchParams.get("q")).toBe('username:"dev\\" or username\\:\\*"');
    expect(url.searchParams.get("search_engine")).toBe("v3");
  });

  it("fails closed on a full username search page", async () => {
    const { client, fetcher } = fixture(Array.from({ length: 100 }, () => profile("devdb", "dev")));
    await expect(client.authenticate("dev", "password")).rejects.toMatchObject({ status: 503 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("logs grant type and OAuth error code for token rejections without credentials", async () => {
    const { client } = fixture([profile()], Response.json({
      error: "unauthorized_client",
      error_description: "Grant type 'http://auth0.com/oauth/grant-type/password-realm' not allowed for the client.",
    }, { status: 403 }));
    await expect(client.authenticate("devuser", "Secret-Pass-123")).rejects.toMatchObject({ status: 503 });
    const logs = JSON.stringify(vi.mocked(console.error).mock.calls);
    expect(logs).toContain("unauthorized_client");
    expect(logs).toContain("password-realm");
    expect(logs).not.toContain("Secret-Pass-123");
    expect(logs).not.toContain("web-secret");
  });

  it("does not fall back to another DB on a wrong password", async () => {
    const { client, fetcher } = fixture([profile()], Response.json({ error: "invalid_grant" }, { status: 403 }));
    await expect(client.authenticate("devuser", "wrong")).rejects.toMatchObject({ status: 401 });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it("reports unsupported MFA without creating an identity", async () => {
    const { client, verify } = fixture([profile()], Response.json({ error: "mfa_required", mfa_token: "secret" }, { status: 403 }));
    await expect(client.authenticate("devuser", "password")).rejects.toMatchObject({ code: "mfa_required" });
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([403, 429, 500])("reports Management API %s as unavailable, not missing user", async (status) => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(managementResponse())
      .mockResolvedValueOnce(Response.json({ error: "provider_error" }, { status }));
    const client = createAuth0Client(config, fetcher);
    await expect(client.authenticate("devuser", "password")).rejects.toMatchObject({ status: 503 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("handles network failures explicitly", async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error("network with sensitive data"));
    await expect(createAuth0Client(config, fetcher).authenticate("dev", "password"))
      .rejects.toMatchObject({ status: 503 });
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("sensitive data");
  });

  it("rejects malformed user response", async () => {
    const { client } = fixture({ users: [] });
    await expect(client.authenticate("devuser", "password")).rejects.toMatchObject({ status: 503 });
  });

  it("rejects a missing ID token", async () => {
    const { client } = fixture([profile()], Response.json({ access_token: "not-an-id-token" }));
    await expect(client.authenticate("devuser", "password")).rejects.toMatchObject({ status: 503 });
  });

  it("rejects a mismatched subject", async () => {
    const { client, verify } = fixture();
    verify.mockResolvedValue({ ...identity(), sub: "auth0|someone-else" });
    await expect(client.authenticate("devuser", "password")).rejects.toMatchObject({ status: 503 });
  });

  it("caches the Management token, not user lookups", async () => {
    const { client, fetcher } = fixture();
    fetcher.mockResolvedValueOnce(Response.json([profile()]))
      .mockResolvedValueOnce(Response.json({ id_token: "id-token" }));
    await client.authenticate("devuser", "password");
    await client.authenticate("devuser", "password");
    expect(fetcher).toHaveBeenCalledTimes(5);
    const grants = fetcher.mock.calls.filter(([, init]) =>
      init?.body && JSON.parse(String(init.body)).grant_type === "client_credentials");
    expect(grants).toHaveLength(1);
  });
});

describe("real ID token cryptographic validation", () => {
  let keys: Awaited<ReturnType<typeof generateKeyPair>>;
  let jwks: { keys: Awaited<ReturnType<typeof exportJWK>>[] };

  beforeAll(async () => {
    keys = await generateKeyPair("RS256");
    jwks = { keys: [{ ...await exportJWK(keys.publicKey), kid: "lab-key", alg: "RS256", use: "sig" }] };
  });

  async function loginWithClaims(overrides: Record<string, unknown> = {}, wrongKey = false) {
    const signingKey = wrongKey ? (await generateKeyPair("RS256")).privateKey : keys.privateKey;
    const token = await new SignJWT({
      ...identity(),
      iss: "https://lab.example.com/",
      aud: "web-client",
      iat: Math.floor(Date.now() / 1000),
      ...overrides,
    }).setProtectedHeader({ alg: "RS256", kid: "lab-key" }).sign(signingKey);
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(managementResponse())
      .mockResolvedValueOnce(Response.json([profile()]))
      .mockResolvedValueOnce(Response.json({ id_token: token }))
      .mockResolvedValueOnce(Response.json(jwks));
    return createAuth0Client(config, fetcher).authenticate("devuser", "password");
  }

  it("accepts a signed token with the expected issuer, audience and subject", async () => {
    await expect(loginWithClaims()).resolves.toMatchObject({ sub: "auth0|123", connection: "devdb" });
  });
  it.each([
    ["wrong issuer", { iss: "https://other.example.com/" }],
    ["wrong audience", { aud: "other-client" }],
    ["expired token", { exp: 1 }],
    ["missing expiration", { exp: undefined }],
    ["wrong subject", { sub: "auth0|other" }],
    ["multi-audience without azp", { aud: ["web-client", "other-client"] }],
    ["wrong authorized party", { azp: "other-client" }],
  ])("rejects %s", async (_name, claims) => {
    await expect(loginWithClaims(claims)).rejects.toMatchObject({ status: 503 });
  });
  it("rejects a forged signature", async () => {
    await expect(loginWithClaims({}, true)).rejects.toMatchObject({ status: 503 });
  });
});
