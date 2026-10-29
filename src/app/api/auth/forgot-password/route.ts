import { AuthError, requestPasswordReset } from "@/lib/auth0";
import { corsJson as reply, corsPreflight, hostedPageOrigin } from "@/lib/cors";
import { readSmallJson } from "@/lib/http";
import { forgotPasswordInput } from "@/lib/login-input";
import { allowPasswordReset } from "@/lib/rate-limit";

export const runtime = "nodejs";

// Same response whether or not the account exists, so the form cannot be used to probe usernames.
const SENT = { ok: true, message: "If an account with that username has an email address, Auth0 has sent a password reset link." };

export function OPTIONS(request: Request) {
  return corsPreflight(request, "forgot-password");
}

export async function POST(request: Request) {
  let origin: string | undefined;
  try {
    origin = hostedPageOrigin(request);
    if (!origin) return reply({ error: "Request origin is not allowed." }, 403, undefined);
    let body: unknown;
    try {
      body = await readSmallJson(request);
    } catch {
      return reply({ error: "Send a valid JSON request (maximum 8 KB)." }, 400, origin);
    }
    const input = forgotPasswordInput.safeParse(body);
    if (!input.success) return reply({ error: "Enter a valid username." }, 400, origin);
    if (!allowPasswordReset(input.data.username)) {
      return reply({ error: "Too many requests. Please wait 15 minutes and try again." }, 429, origin);
    }
    await requestPasswordReset(input.data.username);
    return reply(SENT, 200, origin);
  } catch (error) {
    if (error instanceof AuthError) {
      return reply({ error: "Could not request a password reset right now. Try again later." }, 503, origin);
    }
    console.error("[forgot-password] Internal error; check server configuration");
    return reply({ error: "Server configuration error." }, 500, origin);
  }
}
