"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function LogoutButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function logout() {
    setPending(true);
    setError("");
    try {
      const response = await fetch("/api/auth/logout", { method: "POST" });
      if (!response.ok) {
        setError("Unable to sign out. Please try again.");
        return;
      }
      const body: unknown = await response.json().catch(() => undefined);
      const logoutUrl = typeof body === "object" && body !== null && "logoutUrl" in body &&
        typeof body.logoutUrl === "string" ? body.logoutUrl : undefined;
      if (logoutUrl) {
        window.location.assign(logoutUrl);
        return;
      }
      router.replace("/");
      router.refresh();
    } catch {
      setError("Network error. Please try signing out again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div>
      <button type="button" onClick={logout} disabled={pending}>{pending ? "Signing out..." : "Sign out"}</button>
      {error && <p role="alert" className="error">{error}</p>}
    </div>
  );
}
