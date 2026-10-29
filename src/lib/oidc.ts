import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { z } from "zod";
import { AuthError } from "./auth0";
import type { Config } from "./config";

export type Transaction = {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
};

export type UniversalLoginResult = {
  sub: string;
  name?: string;
  nickname?: string;
  accessToken: string;
  accessTokenExpiresAt: number;
  idTokenExpiresAt: number;
};

const SCOPE = "openid profile";

const base64url = (buffer: Buffer) => buffer.toString("base64url");

export function callbackUrl(config: Config) {
  return `${config.APP_ORIGIN}/auth/callback`;
}

export function createTransaction(now = Date.now()): Transaction {
  return {
    state: base64url(randomBytes(32)),
    nonce: base64url(randomBytes(32)),
    codeVerifier: base64url(randomBytes(32)),
    createdAt: now,
  };
}

export function authorizeUrl(config: Config, transaction: Transaction): string {
  const url = new URL("/authorize", `https://${config.AUTH0_DOMAIN}`);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.AUTH0_CLIENT_ID,
    redirect_uri: callbackUrl(config),
    scope: SCOPE,
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: base64url(createHash("sha256").update(transaction.codeVerifier).digest()),
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

export function logoutUrl(config: Config): string {
  const url = new URL("/v2/logout", `https://${config.AUTH0_DOMAIN}`);
  url.search = new URLSearchParams({ client_id: config.AUTH0_CLIENT_ID, returnTo: config.APP_ORIGIN }).toString();
  return url.toString();
}

type VerifyIdToken = (token: string) => Promise<Record<string, unknown>>;

export function createOidcClient(config: Config, fetcher: typeof fetch = fetch, verifyIdToken?: VerifyIdToken) {
  const issuer = `https://${config.AUTH0_DOMAIN}/`;
  const jwks = createRemoteJWKSet(new URL(".well-known/jwks.json", issuer), { [customFetch]: fetcher });

  async function exchangeCode(code: string, transaction: Transaction): Promise<UniversalLoginResult> {
    let response: Response;
    try {
      response = await fetcher(new URL("oauth/token", issuer), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: config.AUTH0_CLIENT_ID,
          client_secret: config.AUTH0_CLIENT_SECRET,
          code,
          code_verifier: transaction.codeVerifier,
          redirect_uri: callbackUrl(config),
        }),
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      console.error("[oidc] Code exchange network failure");
      throw new AuthError("provider_unavailable", 503);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    if (!response.ok) {
      const error = z.object({ error: z.string() }).safeParse(body);
      const code = error.success && /^[a-z_]{1,64}$/.test(error.data.error) ? error.data.error : undefined;
      console.error(`[oidc] Code exchange rejected ${JSON.stringify({ status: response.status, error: code })}`);
      // invalid_grant: code reused, expired, or PKCE/redirect mismatch. Start login again.
      throw new AuthError(code === "invalid_grant" ? "invalid_credentials" : "provider_unavailable",
        code === "invalid_grant" ? 401 : 503);
    }
    const tokens = z.object({
      access_token: z.string().min(1),
      id_token: z.string().min(1),
      expires_in: z.number().positive(),
      token_type: z.string().regex(/^bearer$/i),
    }).safeParse(body);
    if (!tokens.success) {
      console.error("[oidc] Token response missing access_token or id_token");
      throw new AuthError("provider_unavailable", 503);
    }

    let claims: z.infer<typeof claimsSchema>;
    try {
      const payload = verifyIdToken
        ? await verifyIdToken(tokens.data.id_token)
        : (await jwtVerify(tokens.data.id_token, jwks, {
          issuer,
          audience: config.AUTH0_CLIENT_ID,
          algorithms: ["RS256"],
          requiredClaims: ["sub", "exp", "iat", "nonce"],
        })).payload;
      claims = claimsSchema.parse(payload);
      if (claims.nonce !== transaction.nonce) throw new Error("Nonce mismatch");
      if (claims.exp <= Date.now() / 1000) throw new Error("Expired ID token");
      if ((claims.azp !== undefined && claims.azp !== config.AUTH0_CLIENT_ID) ||
        (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== config.AUTH0_CLIENT_ID)) {
        throw new Error("Unexpected authorized party");
      }
    } catch {
      console.error("[oidc] ID token validation failed");
      throw new AuthError("provider_unavailable", 503);
    }

    return {
      sub: claims.sub,
      name: claims.name,
      nickname: claims.nickname,
      accessToken: tokens.data.access_token,
      accessTokenExpiresAt: Math.floor(Date.now() / 1000) + tokens.data.expires_in,
      idTokenExpiresAt: claims.exp,
    };
  }

  async function userInfo(accessToken: string): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await fetcher(new URL("userinfo", issuer), {
        headers: { Authorization: `Bearer ${accessToken}` },
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new AuthError("provider_unavailable", 503);
    }
    if (response.status === 401) throw new AuthError("invalid_credentials", 401);
    if (!response.ok) throw new AuthError("provider_unavailable", 503);
    const body: unknown = await response.json().catch(() => undefined);
    const parsed = z.record(z.string(), z.unknown()).safeParse(body);
    if (!parsed.success) throw new AuthError("provider_unavailable", 503);
    return parsed.data;
  }

  return { exchangeCode, userInfo };
}

const claimsSchema = z.object({
  sub: z.string().min(1),
  exp: z.number(),
  nonce: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  azp: z.string().optional(),
  name: z.string().optional(),
  nickname: z.string().optional(),
});
