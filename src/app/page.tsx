import { redirect } from "next/navigation";
import Link from "next/link";
import { getConfig } from "@/lib/config";
import { activeUser, getSession } from "@/lib/session";
import { LoginForm } from "@/components/login-form";

export const dynamic = "force-dynamic";

const loginErrors: Record<string, string> = {
  denied: "Auth0 did not complete the sign-in (cancelled, wrong credentials, or the account is not in devdb/ecomdb). Please try again.",
  state: "Your sign-in attempt expired or was opened in another tab. Please start again.",
  auth0: "Sign-in with Auth0 could not be completed. Check the server logs and Auth0 application settings.",
  setup: "Server configuration is incomplete. Check .env.local.",
};

export default async function Home({ searchParams }: { searchParams: Promise<{ error?: string | string[] }> }) {
  const { error } = await searchParams;
  const loginError = typeof error === "string" ? loginErrors[error] : undefined;
  let configurationError: string | undefined;
  let config: ReturnType<typeof getConfig> | undefined;
  try {
    config = getConfig();
  } catch (error) {
    configurationError = error instanceof Error ? error.message : "Invalid server configuration.";
  }
  if (config && activeUser((await getSession()).user)) redirect("/home");

  return (
    <main className="shell">
      <header className="brand"><span className="brand-icon" aria-hidden="true">2</span> AUTH0 / CONNECTION LAB</header>
      <div className="login-grid">
        <section className="intro">
          <p className="eyebrow">TWO DIRECTORIES. ONE APPLICATION.</p>
          <h1>Different databases.<br /><span>Same front door.</span></h1>
          <p className="lead">Sign in with your developer or ecommerce username. The server finds the right database automatically.</p>
          <div className="connections" aria-label="Configured database connections">
            <span><i aria-hidden="true" />{config?.AUTH0_DEV_CONNECTION ?? "devdb"}</span>
            <span><i aria-hidden="true" />{config?.AUTH0_ECOM_CONNECTION ?? "ecomdb"}</span>
          </div>
          <ol className="flow">
            <li><strong>Find the account</strong><span>Server searches the Auth0 Management API.</span></li>
            <li><strong>Resolve its connection</strong><span>No database selector. No guessing.</span></li>
            <li><strong>Authenticate &amp; create a session</strong><span>Password Realm Grant, then an encrypted cookie.</span></li>
          </ol>
        </section>
        <section className="card" aria-labelledby="login-title">
          <p className="eyebrow">WELCOME BACK</p>
          <h2 id="login-title">Sign in to the lab</h2>
          <p className="muted">One account from either database is all you need.</p>
          {configurationError ? (
            <div className="notice" role="alert">
              <strong>Setup required</strong>
              <p>{configurationError}</p>
              <p>Copy .env.example to .env.local, fill in your Auth0 settings, then restart the server. See README.md for instructions.</p>
            </div>
          ) : (
            <>
              {loginError && <p className="error" role="alert">{loginError}</p>}
              {/* Plain link: /auth/login is a route handler that redirects to Auth0. */}
              <a className="button-link" href="/auth/login">Sign in with Auth0</a>
              <p className="hint">Recommended. Auth0&apos;s hosted page handles your password; this app only receives tokens.</p>
              <p className="divider"><span>or use the in-app form (Password Realm Grant)</span></p>
              <LoginForm />
            </>
          )}
          <p className="footnote">New to the lab? <Link href="/signup">Create an account</Link></p>
          <p className="footnote">Sign in with username + password (not email). No MFA or SSO.<br />Forgot your password? Use &quot;Sign in with Auth0&quot;, then &quot;Forgot your password?&quot;.<br />New accounts may take time to appear in Auth0 search.</p>
        </section>
      </div>
      <footer>Next.js + Auth0 <span>Server-side credentials / HttpOnly session</span></footer>
    </main>
  );
}
