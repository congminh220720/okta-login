import { AuthError, connectionForUser } from "@/lib/auth0";
import { getConfig } from "@/lib/config";
import { createOidcClient } from "@/lib/oidc";
import { getSession, getTransactionSession, TRANSACTION_MAX_AGE_MS } from "@/lib/session";

export const runtime = "nodejs";

let oidc: ReturnType<typeof createOidcClient> | undefined;

function redirectTo(path: string) {
  return new Response(null, {
    status: 302,
    headers: { Location: new URL(path, getConfig().APP_ORIGIN).toString(), "Cache-Control": "no-store" },
  });
}

export async function GET(request: Request) {
  try {
    const config = getConfig();
    const params = new URL(request.url).searchParams;
    const tx = await getTransactionSession();
    const transaction = tx.transaction;
    tx.destroy();

    // Auth0 sends error=... when the user cancels or a rule/action denies login.
    if (params.get("error")) {
      const error = params.get("error") ?? "";
      console.warn(`[auth/callback] Auth0 returned error ${JSON.stringify(/^[a-z_]{1,64}$/.test(error) ? error : "unknown")}`);
      return redirectTo(`/?error=${error === "access_denied" ? "denied" : "auth0"}`);
    }
    const code = params.get("code");
    const state = params.get("state");
    if (!transaction || !code || !state || state !== transaction.state ||
      Date.now() - transaction.createdAt > TRANSACTION_MAX_AGE_MS) {
      console.warn("[auth/callback] Missing, expired or mismatched login transaction");
      return redirectTo("/?error=state");
    }

    oidc ??= createOidcClient(config);
    const result = await oidc.exchangeCode(code, transaction);
    const account = await connectionForUser(result.sub);
    const expiresAt = Math.min(result.idTokenExpiresAt, result.accessTokenExpiresAt,
      Math.floor(Date.now() / 1000) + 3600);

    const session = await getSession();
    session.user = {
      sub: result.sub,
      name: (result.name ?? account.username ?? result.nickname ?? result.sub).slice(0, 200),
      username: account.username ?? result.nickname ?? "",
      connection: account.connection,
      expiresAt,
      method: "universal-login",
    };
    session.accessToken = result.accessToken;
    session.accessTokenExpiresAt = result.accessTokenExpiresAt;
    await session.save();
    return redirectTo("/home");
  } catch (error) {
    if (error instanceof AuthError && error.code === "invalid_credentials") return redirectTo("/?error=denied");
    console.error("[auth/callback] Login could not be completed; check server logs and Auth0 configuration");
    try {
      return redirectTo("/?error=auth0");
    } catch {
      return new Response("Login failed: server configuration error.", { status: 500 });
    }
  }
}
