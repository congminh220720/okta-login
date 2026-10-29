import "server-only";
import { cookies } from "next/headers";
import { getIronSession } from "iron-session";
import type { AuthenticatedUser } from "./auth0";
import { getConfig } from "./config";
import type { Transaction } from "./oidc";

type SessionData = {
  user?: AuthenticatedUser;
  // Only set for Universal Login. Kept server-side in the encrypted HttpOnly cookie.
  accessToken?: string;
  accessTokenExpiresAt?: number;
};

type TransactionData = { transaction?: Transaction };

const secure = () => process.env.NODE_ENV === "production";

export async function getSession() {
  return getIronSession<SessionData>(await cookies(), {
    password: getConfig().SESSION_SECRET,
    cookieName: "auth0-db-lab",
    ttl: 3600,
    cookieOptions: { httpOnly: true, secure: secure(), sameSite: "lax", path: "/" },
  });
}

// Short-lived state/nonce/PKCE verifier for one /authorize round trip.
export async function getTransactionSession() {
  return getIronSession<TransactionData>(await cookies(), {
    password: getConfig().SESSION_SECRET,
    cookieName: "auth0-db-lab-tx",
    ttl: 600,
    // Lax is required: Auth0 returns to /auth/callback with a top-level GET redirect.
    cookieOptions: { httpOnly: true, secure: secure(), sameSite: "lax", path: "/auth" },
  });
}

export const TRANSACTION_MAX_AGE_MS = 600_000;

export function activeUser(user: AuthenticatedUser | undefined) {
  return user && user.expiresAt > Date.now() / 1000 ? user : undefined;
}
