import { getConfig } from "@/lib/config";
import { authorizeUrl, createTransaction } from "@/lib/oidc";
import { getTransactionSession } from "@/lib/session";

export const runtime = "nodejs";

// Starts Universal Login: Auth0 shows the (custom) hosted login page and handles credentials.
export async function GET() {
  try {
    const config = getConfig();
    const transaction = createTransaction();
    const tx = await getTransactionSession();
    tx.transaction = transaction;
    await tx.save();
    return new Response(null, {
      status: 302,
      headers: { Location: authorizeUrl(config, transaction), "Cache-Control": "no-store" },
    });
  } catch {
    console.error("[auth/login] Could not start Universal Login; check server configuration");
    return Response.redirect(new URL("/?error=setup", getConfigOrigin()), 302);
  }
}

function getConfigOrigin() {
  try {
    return getConfig().APP_ORIGIN;
  } catch {
    return "http://localhost:3000";
  }
}
