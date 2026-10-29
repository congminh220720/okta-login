import { getConfig } from "@/lib/config";
import { json, sameOrigin } from "@/lib/http";
import { logoutUrl } from "@/lib/oidc";
import { getSession } from "@/lib/session";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
    const session = await getSession();
    const universal = session.user?.method === "universal-login";
    session.destroy();
    // Universal Login also has an Auth0 SSO session; end it so the next login prompts again.
    return json({ ok: true, logoutUrl: universal ? logoutUrl(getConfig()) : undefined });
  } catch {
    console.error("[logout] Failed to clear session; check server configuration");
    return json({ error: "Unable to sign out. Please try again." }, 500);
  }
}
