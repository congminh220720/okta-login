import { authenticate, AuthError } from "@/lib/auth0";
import { json, readSmallJson, sameOrigin } from "@/lib/http";
import { loginInput } from "@/lib/login-input";
import { allowLogin } from "@/lib/rate-limit";
import { getSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
    let body: unknown;
    try {
      body = await readSmallJson(request);
    } catch {
      return json({ error: "Send a valid JSON login request (maximum 8 KB)." }, 400);
    }
    const input = loginInput.safeParse(body);
    if (!input.success) return json({ error: "Enter a username (letters, numbers, dots, underscores or hyphens) and password. Email login is not supported." }, 400);
    if (!allowLogin(input.data.identifier)) {
      return json({ error: "Too many attempts. Please wait 5 minutes and try again." }, 429);
    }
    const user = await authenticate(input.data.identifier, input.data.password);
    const session = await getSession();
    session.user = user;
    await session.save();
    return json({ ok: true });
  } catch (error) {
    if (error instanceof AuthError) {
      const messages = {
        invalid_credentials: "Unable to sign in with these credentials.",
        provider_unavailable: "Authentication service unavailable. Check server configuration or try again later.",
        mfa_required: "This account requires MFA. This password-only lab does not support MFA.",
      };
      return json({ error: messages[error.code] }, error.status);
    }
    console.error("[login] Internal error; check environment and session configuration");
    return json({ error: "Server configuration error. Check .env.local and server logs." }, 500);
  }
}
