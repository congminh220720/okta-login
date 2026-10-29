import Link from "next/link";
import { getConfig } from "@/lib/config";
import { SignupForm } from "@/components/signup-form";

export const dynamic = "force-dynamic";

export default function SignupPage() {
  let config: ReturnType<typeof getConfig> | undefined;
  let configurationError: string | undefined;
  try {
    config = getConfig();
  } catch (error) {
    configurationError = error instanceof Error ? error.message : "Invalid server configuration.";
  }

  return (
    <main className="shell dashboard">
      <header className="brand"><span className="brand-icon" aria-hidden="true">2</span> AUTH0 / CONNECTION LAB</header>
      <section className="card" aria-labelledby="signup-title">
        <p className="eyebrow">CREATE A LAB ACCOUNT</p>
        <h1 id="signup-title">One username.<br /><span>Email for recovery.</span></h1>
        <p className="muted">Choose where to create your account. When you sign in, the app will find that database automatically.</p>
        {config ? (
          <SignupForm connections={[config.AUTH0_DEV_CONNECTION, config.AUTH0_ECOM_CONNECTION]} />
        ) : (
          <div role="alert" className="notice">
            <strong>Setup required</strong>
            <p>{configurationError}</p>
            <p>Fill in .env.local and restart the server. The M2M app needs read:users and create:users.</p>
          </div>
        )}
        <p className="footnote">Lab only: choosing a database does not grant application roles. You sign in with your username; the email is used only by Auth0 for password reset. Your password is not stored by this app.</p>
        <p className="footnote">Already have an account? <Link href="/">Sign in</Link></p>
      </section>
    </main>
  );
}
