import "server-only";
import { createHash } from "node:crypto";

// Local lab only: deploy behind a shared limiter before running multiple instances.
export function createLoginLimiter({ perIdentifier = 10, windowMs = 300_000, globalPerMinute = 60 } = {}) {
  const attempts = new Map<string, { count: number; resetAt: number }>();
  let global = { count: 0, resetAt: 0 };
  return (identifier: string, now = Date.now()) => {
    if (now >= global.resetAt) global = { count: 0, resetAt: now + 60_000 };
    global.count++;
    if (global.count > globalPerMinute) return false;
    for (const [key, entry] of attempts) {
      if (now >= entry.resetAt) attempts.delete(key);
    }
    const key = createHash("sha256").update(identifier.toLowerCase()).digest("hex");
    const entry = attempts.get(key) ?? { count: 0, resetAt: now + windowMs };
    entry.count++;
    attempts.set(key, entry);
    return entry.count <= perIdentifier;
  };
}

export const allowLogin = createLoginLimiter();
export const allowSignup = createLoginLimiter();
export const allowResolve = createLoginLimiter();
// Stricter: each accepted request makes Auth0 send an email.
export const allowPasswordReset = createLoginLimiter({ perIdentifier: 3, windowMs: 900_000, globalPerMinute: 20 });
