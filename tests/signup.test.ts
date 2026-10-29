import { beforeEach, describe, expect, it, vi } from "vitest";
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
const profile = (connection = "devdb") => ({
  user_id: "auth0|new",
  username: "newuser",
  email: "newuser@example.com",
  identities: [{ provider: "auth0", connection }],
});
const managementResponse = () => Response.json({
  access_token: "management-token", expires_in: 3600, token_type: "Bearer",
});

function fixture(users: unknown = [], created = Response.json(profile())) {
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(managementResponse())
    .mockResolvedValueOnce(Response.json(users))
    .mockResolvedValueOnce(created);
  return { fetcher, client: createAuth0Client(config, fetcher) };
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("signup and account lookup", () => {
  describe("password reset request", () => {
    function resetFixture(
      users: unknown,
      resetResponse: Response | Error = new Response("We've just sent you an email to reset your password."),
      byId: unknown = Array.isArray(users) && users.length === 1 ? users[0] : undefined,
    ) {
      const fetcher = vi.fn<typeof fetch>()
        .mockResolvedValueOnce(managementResponse())
        .mockResolvedValueOnce(Response.json(users));
      if (byId !== undefined) fetcher.mockResolvedValueOnce(Response.json(byId));
      if (resetResponse instanceof Error) fetcher.mockRejectedValueOnce(resetResponse);
      else fetcher.mockResolvedValueOnce(resetResponse);
      return { fetcher, client: createAuth0Client(config, fetcher) };
    }

    it.each(["devdb", "ecomdb"])("sends Auth0 change_password for the user's email and %s", async (connection) => {
      const { client, fetcher } = resetFixture([profile(connection)]);
      await client.requestPasswordReset("newuser");
      expect(String(fetcher.mock.calls[2][0])).toContain("/api/v2/users/auth0%7Cnew?");
      const [url, init] = fetcher.mock.calls[3];
      expect(String(url)).toBe("https://lab.example.com/dbconnections/change_password");
      expect(JSON.parse(String(init?.body))).toEqual({
        client_id: "web-client", email: "newuser@example.com", connection,
      });
    });

    it.each([
      ["unknown username", [], 2],
      ["user without email", [{ ...profile(), email: undefined }], 3],
      ["duplicate accounts", [profile("devdb"), profile("ecomdb")], 2],
    ])("silently skips %s without calling Auth0 reset", async (_label, users, calls) => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      const { client, fetcher } = resetFixture(users);
      await expect(client.requestPasswordReset("newuser")).resolves.toBeUndefined();
      expect(fetcher).toHaveBeenCalledTimes(calls);
      expect(fetcher.mock.calls.some(([url]) => String(url).includes("change_password"))).toBe(false);
    });

    it("uses the current email when search results are stale", async () => {
      const { client, fetcher } = resetFixture([{ ...profile(), email: undefined }], undefined, profile());
      await client.requestPasswordReset("newuser");
      expect(JSON.parse(String(fetcher.mock.calls[3][1]?.body))).toMatchObject({ email: "newuser@example.com" });
    });

    it.each([
      [new Response("sensitive newuser@example.com", { status: 400 })],
      [new Error("network")],
    ])("reports Auth0 reset failures without logging the email (%#)", async (response) => {
      const { client } = resetFixture([profile()], response);
      await expect(client.requestPasswordReset("newuser")).rejects.toMatchObject({ status: 503 });
      expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("@example.com");
    });
  });

  it("finds the single allowed connection for a user id", async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(managementResponse())
      .mockResolvedValueOnce(Response.json(profile("ecomdb")));
    const client = createAuth0Client(config, fetcher);
    await expect(client.connectionForUser("auth0|new")).resolves.toEqual({ connection: "ecomdb", username: "newuser" });
    expect(String(fetcher.mock.calls[1][0])).toContain("/api/v2/users/auth0%7Cnew?");
  });

  it.each([
    [{ ...profile("otherdb") }],
    [{ ...profile(), identities: [...profile().identities, ...profile("ecomdb").identities] }],
    [{ ...profile(), user_id: "auth0|someone-else" }],
  ])("rejects users that are not exactly one allowed identity (%#)", async (user) => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(managementResponse())
      .mockResolvedValueOnce(Response.json(user));
    await expect(createAuth0Client(config, fetcher).connectionForUser("auth0|new"))
      .rejects.toMatchObject({ code: "invalid_credentials" });
  });

  it("resolves a username to its single connection without logging in", async () => {
    const { client, fetcher } = fixture([profile("ecomdb")]);
    await expect(client.resolveConnection("newuser")).resolves.toBe("ecomdb");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it.each([[[]], [[profile("devdb"), profile("ecomdb")]], [[profile("otherdb")]]])(
    "returns no connection when lookup is not exactly one allowed identity", async (users) => {
      const { client } = fixture(users);
      await expect(client.resolveConnection("newuser")).resolves.toBeUndefined();
    },
  );

  it.each(["devdb", "ecomdb"])("creates a username-only user in %s", async (connection) => {
    const { client, fetcher } = fixture([], Response.json(profile(connection)));
    await client.signup("newuser", " password ", connection, "newuser@example.com");
    const [url, init] = fetcher.mock.calls[2];
    expect(String(url)).toBe("https://lab.example.com/api/v2/users");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      username: "newuser", email: "newuser@example.com", password: " password ", connection,
    });
    expect(init?.headers).toMatchObject({ Authorization: "Bearer management-token" });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it.each(["devdb", "ecomdb"])("blocks a username already in %s, even when choosing the other DB", async (connection) => {
    const { client, fetcher } = fixture([profile(connection)]);
    await expect(client.signup("newuser", "password", connection === "devdb" ? "ecomdb" : "devdb", "newuser@example.com"))
      .rejects.toMatchObject({ code: "username_unavailable", status: 409 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("rejects a third connection before any request", async () => {
    const { client, fetcher } = fixture();
    await expect(client.signup("newuser", "password", "otherdb", "newuser@example.com")).rejects.toMatchObject({ status: 400 });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("blocks concurrent and recently completed same-username creation across connections", async () => {
    const { client, fetcher } = fixture();
    const first = client.signup("newuser", "password", "devdb", "newuser@example.com");
    await expect(client.signup("newuser", "password", "ecomdb", "newuser@example.com")).rejects.toMatchObject({ status: 409 });
    await first;
    await expect(client.signup("newuser", "password", "ecomdb", "newuser@example.com")).rejects.toMatchObject({ status: 409 });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it.each([
    [400, "signup_rejected", 400],
    [409, "username_unavailable", 409],
    [403, "provider_unavailable", 503],
    [429, "provider_unavailable", 503],
    [500, "provider_unavailable", 503],
  ])("handles Auth0 create HTTP %s explicitly", async (status, code, expectedStatus) => {
    vi.stubEnv("NODE_ENV", "production");
    const { client } = fixture([], Response.json({ error: "upstream-error", message: "sensitive-provider-body" }, { status }));
    await expect(client.signup("newuser", "password", "devdb", "newuser@example.com"))
      .rejects.toMatchObject({ code, status: expectedStatus });
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("sensitive-provider-body");
    vi.unstubAllEnvs();
  });

  it("allows retry after a definitive password policy rejection", async () => {
    const { client, fetcher } = fixture([], Response.json({ error: "Bad Request" }, { status: 400 }));
    await expect(client.signup("newuser", "weakpass", "devdb", "newuser@example.com")).rejects.toMatchObject({ status: 400 });
    fetcher.mockResolvedValueOnce(Response.json([])).mockResolvedValueOnce(Response.json(profile()));
    await expect(client.signup("newuser", "BetterPassword123!", "devdb", "newuser@example.com")).resolves.toBeUndefined();
  });

  it.each([
    [{ error: "Bad Request", message: "Payload validation error: 'Missing required property: email'." }, "email_required"],
    [{ message: "Email is required" }, "email_required"],
    [{ message: "Username is not allowed for this connection." }, "username_not_enabled"],
    [{ error: "PasswordStrengthError", message: "Password is too weak" }, "password_policy"],
    [{ error: "Bad Request", name: "PasswordDictionaryError" }, "password_policy"],
    [{ errorCode: "PasswordLeakedError" }, "password_policy"],
    [{ error_description: "PasswordNoUserInfoError: Password contains user information" }, "password_policy"],
    [{ message: "The connection is disabled" }, "connection_disabled"],
    [{ message: "Payload validation error: '\"username\" does not meet length criteria.'." }, "username_length"],
    [{ message: "Unsupported password setting" }, "signup_rejected"],
    [{ message: "Invalid username length" }, "signup_rejected"],
  ])("classifies a known Auth0 validation error without guessing unknown errors", async (body, code) => {
    const { client } = fixture([], Response.json(body, { status: 400 }));
    await expect(client.signup("newuser", "password", "devdb", "newuser@example.com")).rejects.toMatchObject({ code, status: 400 });
    expect(vi.mocked(console.error)).toHaveBeenCalledWith(expect.stringContaining(`"reason":"${code}"`));
  });

  it("logs masked Auth0 validation detail in development for unknown 400s", async () => {
    const { client } = fixture([], Response.json({
      message: "Payload validation error: 'String is too long (20 chars), maximum 15' on property username (newuser).",
    }, { status: 400 }));
    await expect(client.signup("newuser", "Secret-Pass-123", "devdb", "newuser@example.com")).rejects.toMatchObject({ code: "signup_rejected" });
    const logs = JSON.stringify(vi.mocked(console.error).mock.calls);
    expect(logs).toContain("maximum 15");
    expect(logs).toContain("[redacted]");
    expect(logs).not.toContain("(newuser)");
    expect(logs).not.toContain("Secret-Pass-123");
  });

  it("keeps provider messages and credentials out of errors and logs", async () => {
    const secret = "private-value-not-for-browser";
    const { client } = fixture([], Response.json({
      error: secret,
      message: `Payload validation error: 'Missing required property: email'. Input: ${secret}`,
    }, { status: 400 }));
    await expect(client.signup("newuser", secret, "devdb", "newuser@example.com")).rejects.toMatchObject({
      code: "email_required", message: "email_required",
    });
    const logs = JSON.stringify(vi.mocked(console.error).mock.calls);
    expect(logs).not.toContain(secret);
    expect(logs).toContain('\\"status\\":400');
    expect(logs).toContain('\\"method\\":\\"POST\\"');
  });

  it("does not report malformed creation responses as success", async () => {
    const { client } = fixture([], Response.json({}));
    await expect(client.signup("newuser", "password", "devdb", "newuser@example.com")).rejects.toMatchObject({ status: 503 });
  });

  it("does not write if lookup fails", async () => {
    const { client, fetcher } = fixture({ users: [] });
    await expect(client.signup("newuser", "password", "devdb", "newuser@example.com")).rejects.toMatchObject({ status: 503 });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("retains a reservation after an uncertain write to avoid immediate duplicate creation", async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(managementResponse())
      .mockResolvedValueOnce(Response.json([]))
      .mockRejectedValueOnce(new Error("timeout"));
    const client = createAuth0Client(config, fetcher);
    await expect(client.signup("newuser", "password", "devdb", "newuser@example.com")).rejects.toMatchObject({ status: 503 });
    await expect(client.signup("newuser", "password", "ecomdb", "newuser@example.com")).rejects.toMatchObject({ status: 409 });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
});
