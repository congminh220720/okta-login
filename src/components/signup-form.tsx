"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

export function SignupForm({ connections }: { connections: string[] }) {
  const [pending, setPending] = useState(false);
  const [created, setCreated] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setError("");
    setPending(true);
    try {
      const response = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: data.get("username"),
          email: data.get("email"),
          password: data.get("password"),
          connection: data.get("connection"),
        }),
      });
      const body: unknown = await response.json();
      if (!response.ok) {
        setError(typeof body === "object" && body !== null && "error" in body &&
          typeof body.error === "string" ? body.error : "Account creation failed. Please try again.");
        return;
      }
      form.reset();
      setCreated(true);
    } catch {
      setError("Could not confirm account creation. Check your connection; creation may have completed. Try signing in before submitting again.");
    } finally {
      data.delete("password");
      const passwordInput = form.elements.namedItem("password");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
      setPending(false);
    }
  }

  return (
    <div>
      <div aria-live="polite" aria-atomic="true">
        {created && (
          <div className="notice">
            <strong>Account created.</strong>
            <p>Auth0 username search may take time to update. If login does not find your account yet, wait and try again. You do not need to register again.</p>
            <Link href="/">Continue to sign in</Link>
          </div>
        )}
      </div>
      {!created && (
        <form onSubmit={submit} className="auth-form" aria-busy={pending}>
          <label htmlFor="username">Username</label>
          <input id="username" name="username" autoComplete="username" autoCapitalize="none"
            spellCheck={false} maxLength={128} pattern="[A-Za-z0-9._\-]+" required disabled={pending} aria-describedby="username-hint" />
          <p id="username-hint" className="hint">Letters, numbers, dots, underscores or hyphens; saved as lowercase. Use a unique username across both databases. Auth0 may enforce a shorter length.</p>
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="email" autoCapitalize="none"
            spellCheck={false} maxLength={254} required disabled={pending} aria-describedby="email-hint" />
          <p id="email-hint" className="hint">Used only by Auth0 to send password reset links. You still sign in with your username.</p>
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="new-password"
            minLength={8} maxLength={1024} required disabled={pending} aria-describedby="password-hint" />
          <p id="password-hint" className="hint">At least 8 characters. The selected Auth0 database&apos;s password policy also applies.</p>
          <label htmlFor="connection">Database connection</label>
          <select id="connection" name="connection" required disabled={pending} defaultValue="">
            <option value="" disabled>Select a database</option>
            {connections.map((connection) => <option key={connection} value={connection}>{connection}</option>)}
          </select>
          <div aria-live="polite" aria-atomic="true">
            {error && <p className="error" role="alert">{error}</p>}
            {pending && <p className="hint">Creating your account in Auth0...</p>}
          </div>
          <button type="submit" disabled={pending}>{pending ? "Creating account..." : "Create account"}</button>
        </form>
      )}
    </div>
  );
}
