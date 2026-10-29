import { AuthError, resolveConnection } from "@/lib/auth0";
import { corsJson as reply, corsPreflight, hostedPageOrigin } from "@/lib/cors";
import { readSmallJson } from "@/lib/http";
import { usernameInput } from "@/lib/login-input";
import { allowResolve } from "@/lib/rate-limit";
import { z } from "zod";

export const runtime = "nodejs";

const resolveInput = z.object({ username: usernameInput }).strict();

export function OPTIONS(request: Request) {
  return corsPreflight(request, "resolve-connection");
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
    const input = resolveInput.safeParse(body);
    if (!input.success) return reply({ error: "Enter a valid username." }, 400, origin);
    if (!allowResolve(input.data.username)) {
      return reply({ error: "Too many attempts. Please wait 5 minutes and try again." }, 429, origin);
    }
    const connection = await resolveConnection(input.data.username);
    if (!connection) return reply({ error: "not_found" }, 404, origin);
    return reply({ connection }, 200, origin);
  } catch (error) {
    if (error instanceof AuthError) {
      return reply({ error: "Authentication service unavailable. Try again later." }, 503, origin);
    }
    console.error("[resolve-connection] Internal error; check server configuration");
    return reply({ error: "Server configuration error." }, 500, origin);
  }
}
