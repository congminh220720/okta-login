import "server-only";
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { z } from "zod";
import { getConfig, type Config } from "./config";

export class AuthError extends Error {
  constructor(
    public readonly code: "invalid_credentials" | "provider_unavailable" | "mfa_required",
    public readonly status: number,
  ) {
    super(code);
  }
}

export class SignupError extends Error {
  constructor(
    public readonly code: "username_unavailable" | "signup_rejected" | "invalid_connection" |
      "email_required" | "username_not_enabled" | "password_policy" | "connection_disabled" | "username_length",
    public readonly status: number,
  ) {
    super(code);
  }
}

const providerErrorSchema = z.object({
  error: z.string().optional(),
  errorCode: z.string().optional(),
  name: z.string().optional(),
  message: z.string().optional(),
  error_description: z.string().optional(),
});

function signupRejection(error: z.infer<typeof providerErrorSchema> | undefined): SignupError["code"] {
  const descriptions = [error?.message, error?.error_description].filter(
    (value): value is string => typeof value === "string",
  );
  if (descriptions.some((message) => /^the connection is disabled\.?$/i.test(message))) {
    return "connection_disabled";
  }
  if (descriptions.some((message) => /"?username"? does not meet length criteria/i.test(message))) {
    return "username_length";
  }
  if (descriptions.some((message) =>
    /missing required property:\s*['"]?email\b/i.test(message) ||
    /^(?:email is required|email is required for this connection)\.?$/i.test(message))) {
    return "email_required";
  }
  if (descriptions.some((message) =>
    /^username is not allowed(?: for this connection)?\.?$/i.test(message) ||
    /cannot set username for (?:a )?connection without requires_username/i.test(message))) {
    return "username_not_enabled";
  }
  const passwordErrors = [
    "PasswordStrengthError", "PasswordDictionaryError", "PasswordNoUserInfoError",
    "PasswordHistoryError", "PasswordLeakedError",
  ];
  if ([error?.error, error?.errorCode, error?.name].some(
    (code) => code !== undefined && passwordErrors.includes(code),
  ) || descriptions.some((message) =>
    /^password is too weak\.?$/i.test(message) ||
    passwordErrors.some((code) => message.startsWith(`${code}:`)))) {
    return "password_policy";
  }
  return "signup_rejected";
}

// Local development only: Auth0 error text with submitted credentials masked.
function redactedDetail(
  error: z.infer<typeof providerErrorSchema> | undefined,
  body: RequestInit["body"],
): string | undefined {
  if (process.env.NODE_ENV === "production") return undefined;
  const detail = error?.message ?? error?.error_description;
  if (!detail) return undefined;
  let secrets: string[] = [];
  try {
    const parsed = z.object({
      username: z.string(), password: z.string(), client_secret: z.string(),
    }).partial().safeParse(JSON.parse(String(body)));
    if (parsed.success) {
      secrets = [parsed.data.password, parsed.data.username, parsed.data.client_secret]
        .filter((value): value is string => typeof value === "string" && value.length > 0);
    }
  } catch {
    return undefined;
  }
  let redacted = detail;
  for (const value of secrets.sort((a, b) => b.length - a.length)) {
    redacted = redacted.split(value).join("[redacted]");
  }
  return redacted.slice(0, 300);
}

const userSchema = z.object({
  user_id: z.string().min(1),
  username: z.string().optional(),
  email: z.string().optional(),
  identities: z.array(z.object({
    provider: z.string(),
    connection: z.string(),
  })),
});

export type AuthenticatedUser = {
  sub: string;
  name: string;
  username: string;
  connection: string;
  expiresAt: number;
  method?: "password-realm" | "universal-login";
};

type VerifiedIdentity = {
  sub: string;
  exp: number;
  name?: string;
};

type VerifyToken = (token: string) => Promise<VerifiedIdentity>;

// Auth0 username search is eventually consistent; newly created users may appear later.
function quotedSearch(value: string): string {
  return `"${value.replace(/[+\-=&|><!(){}[\]^"~*?:\\/]/g, "\\$&")}"`;
}

export function createAuth0Client(config: Config, fetcher: typeof fetch = fetch, verify?: VerifyToken) {
  const issuer = `https://${config.AUTH0_DOMAIN}/`;
  const jwks = createRemoteJWKSet(new URL(".well-known/jwks.json", issuer), {
    [customFetch]: fetcher,
  });
  const connections = [config.AUTH0_DEV_CONNECTION, config.AUTH0_ECOM_CONNECTION];
  let managementToken: { value: string; expiresAt: number } | undefined;
  let pendingToken: Promise<string> | undefined;
  const signupReservations = new Map<string, number>();

  async function request(path: string, init: RequestInit, purpose?: "login" | "signup"): Promise<unknown> {
    let response: Response;
    try {
      response = await fetcher(new URL(path, issuer), {
        ...init,
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      console.error("[auth0] Network request failed", { endpoint: path.split("?")[0] });
      throw new AuthError("provider_unavailable", 503);
    }

    if (!response.ok) {
      let providerError: z.infer<typeof providerErrorSchema> | undefined;
      try {
        const body: unknown = await response.json();
        const parsed = providerErrorSchema.safeParse(body);
        if (parsed.success) providerError = parsed.data;
      } catch {
        console.error("[auth0] Non-JSON error response", { status: response.status });
      }
      const code = providerError?.error;
      const rejection = purpose === "signup" && response.status === 400
        ? signupRejection(providerError) : undefined;
      // Never log raw provider bodies; detail is dev-only and masks submitted credentials.
      let grant: string | undefined;
      try {
        const parsedGrant = z.object({ grant_type: z.string() })
          .safeParse(JSON.parse(String(init.body)));
        if (parsedGrant.success) grant = parsedGrant.data.grant_type;
      } catch {
        grant = undefined;
      }
      console.error(`[auth0] Request rejected ${JSON.stringify({
        endpoint: path.split("?")[0],
        method: init.method ?? "GET",
        status: response.status,
        grant,
        error: code && /^[a-z_]{1,64}$/.test(code) ? code : undefined,
        reason: rejection,
        detail: redactedDetail(providerError, init.body),
      })}`);
      if (purpose === "signup" && response.status === 409) {
        throw new SignupError("username_unavailable", 409);
      }
      if (purpose === "signup" && response.status === 400) {
        throw new SignupError(rejection ?? "signup_rejected", 400);
      }
      if (purpose === "login" && code === "mfa_required") throw new AuthError("mfa_required", 403);
      if (purpose === "login" && ["invalid_grant", "access_denied"].includes(code ?? "")) {
        throw new AuthError("invalid_credentials", 401);
      }
      throw new AuthError("provider_unavailable", 503);
    }

    try {
      return await response.json();
    } catch {
      console.error("[auth0] Invalid JSON response", { endpoint: path.split("?")[0] });
      throw new AuthError("provider_unavailable", 503);
    }
  }

  async function getManagementToken(): Promise<string> {
    if (managementToken && managementToken.expiresAt > Date.now()) return managementToken.value;
    if (pendingToken) return pendingToken;
    pendingToken = (async () => {
      const body = await request("oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "client_credentials",
          client_id: config.AUTH0_MANAGEMENT_CLIENT_ID,
          client_secret: config.AUTH0_MANAGEMENT_CLIENT_SECRET,
          audience: `${issuer}api/v2/`,
        }),
      });
      const token = z.object({
        access_token: z.string().min(1),
        expires_in: z.number().positive(),
        token_type: z.literal("Bearer"),
      }).safeParse(body);
      if (!token.success) {
        console.error("[auth0] Invalid Management token response");
        throw new AuthError("provider_unavailable", 503);
      }
      managementToken = {
        value: token.data.access_token,
        expiresAt: Date.now() + Math.max(0, token.data.expires_in - 60) * 1000,
      };
      return managementToken.value;
    })();
    try {
      return await pendingToken;
    } finally {
      pendingToken = undefined;
    }
  }

  async function findCandidates(identifier: string, token: string) {
    const params = new URLSearchParams({
      fields: "user_id,username,email,identities",
      include_fields: "true",
      q: `username:${quotedSearch(identifier)}`,
      search_engine: "v3",
      per_page: "100",
      page: "0",
    });
    const result = await request(`api/v2/users?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const users = z.array(userSchema).safeParse(result);
    if (!users.success) {
      console.error("[auth0] Invalid user search response");
      throw new AuthError("provider_unavailable", 503);
    }
    // Fail closed rather than choose from a potentially truncated search result.
    if (users.data.length >= 100) {
      console.error("[auth0] Username search reached pagination limit");
      throw new AuthError("provider_unavailable", 503);
    }
    return users.data.flatMap((user) => {
      if (user.username?.toLowerCase() !== identifier) return [];
      return user.identities
        .filter((identity) => identity.provider === "auth0" && connections.includes(identity.connection))
        .map((identity) => ({ sub: user.user_id, connection: identity.connection, email: user.email }));
    });
  }

  // Asks Auth0 to email a reset link. Always resolves the same way so callers cannot
  // learn whether the username exists or has an email.
  async function requestPasswordReset(username: string): Promise<void> {
    const token = await getManagementToken();
    const candidates = await findCandidates(username, token);
    // User search is eventually consistent; re-read the user so a recently added email is used.
    const current = candidates.length === 1
      ? userSchema.safeParse(await request(`api/v2/users/${encodeURIComponent(candidates[0].sub)}?${new URLSearchParams({
        fields: "user_id,username,email,identities", include_fields: "true",
      })}`, { headers: { Authorization: `Bearer ${token}` } }))
      : undefined;
    const email = current?.success && current.data.user_id === candidates[0].sub ? current.data.email : undefined;
    if (candidates.length !== 1 || !email) {
      console.warn(`[auth0] Password reset skipped ${JSON.stringify({
        reason: candidates.length !== 1 ? "no_single_account" : "no_email",
      })}`);
      return;
    }
    let response: Response;
    try {
      response = await fetcher(new URL("dbconnections/change_password", issuer), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: config.AUTH0_CLIENT_ID,
          email,
          connection: candidates[0].connection,
        }),
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      console.error("[auth0] Password reset request network failure");
      throw new AuthError("provider_unavailable", 503);
    }
    if (!response.ok) {
      // Body may echo the email address; log status only.
      console.error(`[auth0] Password reset request rejected ${JSON.stringify({ status: response.status })}`);
      throw new AuthError("provider_unavailable", 503);
    }
  }

  async function signup(username: string, password: string, connection: string, email: string): Promise<void> {
    if (!connections.includes(connection)) throw new SignupError("invalid_connection", 400);
    for (const [key, expiresAt] of signupReservations) {
      if (expiresAt <= Date.now()) signupReservations.delete(key);
    }
    if (signupReservations.has(username)) throw new SignupError("username_unavailable", 409);
    // Bridges concurrent requests and search-index lag in this single-process lab only.
    signupReservations.set(username, Date.now() + 600_000);
    let creationAttempted = false;
    try {
      const token = await getManagementToken();
      if ((await findCandidates(username, token)).length > 0) {
        throw new SignupError("username_unavailable", 409);
      }
      creationAttempted = true;
      const response = await request("api/v2/users", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ connection, username, email, password }),
      }, "signup");
      const created = userSchema.safeParse(response);
      if (!created.success || created.data.username?.toLowerCase() !== username ||
        created.data.email?.toLowerCase() !== email ||
        !created.data.identities.some((identity) =>
          identity.provider === "auth0" && identity.connection === connection)) {
        console.error("[auth0] Invalid create-user response; check Auth0 before retrying");
        throw new AuthError("provider_unavailable", 503);
      }
    } catch (error) {
      // A timed-out write may have succeeded: retain the reservation in that case.
      if (!creationAttempted || error instanceof SignupError) signupReservations.delete(username);
      throw error;
    }
  }

  async function authenticate(identifier: string, password: string): Promise<AuthenticatedUser> {
    const token = await getManagementToken();
    const candidates = await findCandidates(identifier, token);
    if (candidates.length !== 1) {
      console.warn("[auth0] Lookup did not resolve to one database identity");
      throw new AuthError("invalid_credentials", 401);
    }

    const candidate = candidates[0];
    const response = await request("oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        client_id: config.AUTH0_CLIENT_ID,
        client_secret: config.AUTH0_CLIENT_SECRET,
        username: identifier,
        password,
        realm: candidate.connection,
        scope: "openid profile",
      }),
    }, "login");
    const tokens = z.object({ id_token: z.string().min(1) }).safeParse(response);
    if (!tokens.success) {
      console.error("[auth0] Login response has no ID token");
      throw new AuthError("provider_unavailable", 503);
    }
    let identity: VerifiedIdentity;
    try {
      if (verify) {
        identity = await verify(tokens.data.id_token);
      } else {
        const { payload } = await jwtVerify(tokens.data.id_token, jwks, {
          issuer,
          audience: config.AUTH0_CLIENT_ID,
          algorithms: ["RS256"],
          requiredClaims: ["sub", "exp", "iat"],
        });
        if ((payload.azp !== undefined && payload.azp !== config.AUTH0_CLIENT_ID) ||
          (Array.isArray(payload.aud) && payload.aud.length > 1 &&
            payload.azp !== config.AUTH0_CLIENT_ID)) {
          throw new Error("Unexpected authorized party");
        }
        identity = z.object({
          sub: z.string().min(1),
          exp: z.number(),
          name: z.string().optional(),
        }).parse(payload);
      }
      if (identity.sub !== candidate.sub || identity.exp <= Date.now() / 1000) {
        throw new Error("Identity mismatch or expired token");
      }
    } catch {
      console.error("[auth0] ID token validation failed");
      throw new AuthError("provider_unavailable", 503);
    }
    return {
      sub: identity.sub,
      name: (identity.name ?? identifier).slice(0, 200),
      username: identifier,
      connection: candidate.connection,
      expiresAt: Math.min(identity.exp, Math.floor(Date.now() / 1000) + 3600),
      method: "password-realm",
    };
  }

  // Used by the Auth0-hosted login page, which cannot hold Management API credentials.
  async function resolveConnection(identifier: string): Promise<string | undefined> {
    const token = await getManagementToken();
    const candidates = await findCandidates(identifier, token);
    return candidates.length === 1 ? candidates[0].connection : undefined;
  }

  // The ID token does not say which database authenticated the user; ask the Management API.
  async function connectionForUser(userId: string): Promise<{ connection: string; username?: string }> {
    const token = await getManagementToken();
    const params = new URLSearchParams({ fields: "user_id,username,identities", include_fields: "true" });
    const result = await request(`api/v2/users/${encodeURIComponent(userId)}?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const user = userSchema.safeParse(result);
    const identities = user.success
      ? user.data.identities.filter((identity) =>
        identity.provider === "auth0" && connections.includes(identity.connection))
      : [];
    if (!user.success || user.data.user_id !== userId || identities.length !== 1) {
      console.error("[auth0] User does not map to exactly one allowed database connection");
      throw new AuthError("invalid_credentials", 401);
    }
    return { connection: identities[0].connection, username: user.data.username };
  }

  return { authenticate, signup, resolveConnection, connectionForUser, requestPasswordReset };
}

let client: ReturnType<typeof createAuth0Client> | undefined;

export function requestPasswordReset(username: string) {
  client ??= createAuth0Client(getConfig());
  return client.requestPasswordReset(username);
}

export function connectionForUser(userId: string) {
  client ??= createAuth0Client(getConfig());
  return client.connectionForUser(userId);
}

export function resolveConnection(identifier: string) {
  client ??= createAuth0Client(getConfig());
  return client.resolveConnection(identifier);
}

export function authenticate(identifier: string, password: string) {
  client ??= createAuth0Client(getConfig());
  return client.authenticate(identifier, password);
}

export function signup(username: string, password: string, connection: string, email: string) {
  client ??= createAuth0Client(getConfig());
  return client.signup(username, password, connection, email);
}
