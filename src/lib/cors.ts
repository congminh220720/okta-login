import "server-only";
import { getConfig, loginPageOrigins } from "./config";

// CORS for endpoints called by the Auth0-hosted login page (a different origin from this app).
export function hostedPageOrigin(request: Request): string | undefined {
  const origin = request.headers.get("origin");
  return origin && loginPageOrigins(getConfig()).includes(origin) ? origin : undefined;
}

export function corsHeaders(origin: string | undefined): Record<string, string> {
  const headers: Record<string, string> = { "Cache-Control": "no-store", Vary: "Origin" };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

export function corsJson(body: unknown, status: number, origin: string | undefined) {
  return Response.json(body, { status, headers: corsHeaders(origin) });
}

export function corsPreflight(request: Request, logTag: string) {
  try {
    const origin = hostedPageOrigin(request);
    if (!origin) return new Response(null, { status: 403, headers: corsHeaders(undefined) });
    const headers = {
      ...corsHeaders(origin),
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "600",
    } as Record<string, string>;
    // Chrome Private/Local Network Access preflight when a public page calls localhost.
    if (request.headers.get("access-control-request-private-network") === "true") {
      headers["Access-Control-Allow-Private-Network"] = "true";
    }
    return new Response(null, { status: 204, headers });
  } catch {
    console.error(`[${logTag}] Preflight failed; check server configuration`);
    return new Response(null, { status: 500, headers: corsHeaders(undefined) });
  }
}
