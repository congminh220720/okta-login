"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";

export function LoginForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setError("");
    setPending(true);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identifier: data.get("identifier"),
          password: data.get("password"),
        }),
      });
      const body: unknown = await response.json();
      if (!response.ok) {
        setError(typeof body === "object" && body !== null && "error" in body &&
          typeof body.error === "string" ? body.error : "Sign-in failed. Please try again.");
        return;
      }
      form.reset();
      router.replace("/home");
      router.refresh();
    } catch {
      setError("Could not reach the application. Check your connection and try again.");
    } finally {
      data.delete("password");
      const passwordInput = form.elements.namedItem("password");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} className="auth-form" aria-busy={pending}>
      <label htmlFor="identifier">Username</label>
      <input id="identifier" name="identifier" autoComplete="username" autoCapitalize="none"
        spellCheck={false} maxLength={128} pattern="[A-Za-z0-9._\-]+" required disabled={pending} aria-describedby="identifier-hint" />
      <p id="identifier-hint" className="hint">Letters, numbers, dots, underscores or hyphens. Usernames are lowercased; email login is not supported.</p>
      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" autoComplete="current-password"
        maxLength={1024} required disabled={pending} />
      <div aria-live="polite" aria-atomic="true">
        {error && <p className="error" role="alert">{error}</p>}
        {pending && <p className="hint">Finding your account and signing you in...</p>}
      </div>
      <button type="submit" disabled={pending}>{pending ? "Signing in..." : "Sign in"}</button>
    </form>
  );
}
