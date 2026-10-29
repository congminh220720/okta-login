import { redirect } from "next/navigation";
import { AuthError } from "@/lib/auth0";
import { getConfig } from "@/lib/config";
import { createOidcClient } from "@/lib/oidc";
import { activeUser, getSession } from "@/lib/session";
import { LogoutButton } from "@/components/logout-button";

export const dynamic = "force-dynamic";

async function loadUserInfo(accessToken: string | undefined) {
  if (!accessToken) return { state: "none" as const };
  try {
    const info = await createOidcClient(getConfig()).userInfo(accessToken);
    return { state: "ok" as const, info };
  } catch (error) {
    const expired = error instanceof AuthError && error.code === "invalid_credentials";
    if (!expired) console.error("[home] /userinfo call failed");
    return { state: expired ? "expired" as const : "error" as const };
  }
}

const utc = (seconds: number) => new Date(seconds * 1000).toISOString().replace(".000Z", "Z");

export default async function HomePage() {
  const session = await getSession();
  const user = activeUser(session.user);
  if (!user) redirect("/");
  const universal = user.method === "universal-login";
  const userInfo = universal ? await loadUserInfo(session.accessToken) : { state: "none" as const };

  return (
    <main className="shell dashboard">
      <header className="brand"><span className="brand-icon" aria-hidden="true">2</span> AUTH0 / CONNECTION LAB</header>
      <section className="card">
        <p className="eyebrow success">HOME</p>
        <h1>Welcome, {user.name}.</h1>
        <p className="lead">
          You are signed in from <strong>{user.connection}</strong>
          {universal ? " via Auth0 Universal Login." : " via the in-app form (Password Realm Grant)."}
        </p>
        <dl>
          <div><dt>Login method</dt><dd>{universal ? "Auth0 hosted login → Authorization Code + PKCE" : "Password Realm Grant from the Next.js server"}</dd></div>
          <div><dt>Database connection</dt><dd>{user.connection}</dd></div>
          <div><dt>Username</dt><dd>{user.username || "Not set"}</dd></div>
          <div><dt>Auth0 subject</dt><dd>{user.sub}</dd></div>
          <div><dt>Session expires (UTC)</dt><dd>{utc(user.expiresAt)}</dd></div>
          {universal && (
            <div>
              <dt>Access token</dt>
              <dd>
                {session.accessToken
                  ? `Stored server-side in the encrypted HttpOnly session cookie; expires ${utc(session.accessTokenExpiresAt ?? user.expiresAt)}`
                  : "Not available"}
              </dd>
            </div>
          )}
        </dl>

        {universal && (
          <section aria-labelledby="userinfo-title">
            <h2 id="userinfo-title" className="section-title">Token check: Auth0 /userinfo</h2>
            {userInfo.state === "ok" && (
              <>
                <p className="muted">The server called Auth0 with the stored access token. Response:</p>
                <pre className="code">{JSON.stringify(userInfo.info, null, 2)}</pre>
              </>
            )}
            {userInfo.state === "expired" && <p className="notice">The access token was rejected or expired. Sign out and sign in again.</p>}
            {userInfo.state === "error" && <p className="notice">Could not reach Auth0 /userinfo. Your session is still valid; try reloading.</p>}
          </section>
        )}

        <p className="footnote">Tokens are never exposed to browser JavaScript or localStorage. Sign out clears this app session{universal ? " and your Auth0 login session" : ""}.</p>
        <LogoutButton />
      </section>
    </main>
  );
}
