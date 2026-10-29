import { afterEach, describe, expect, it, vi } from "vitest";
import { sealData, unsealData } from "iron-session";
import { loginInput, signupInput } from "@/lib/login-input";
import { createLoginLimiter } from "@/lib/rate-limit";
import { readSmallJson, sameOrigin } from "@/lib/http";
import { activeUser } from "@/lib/session";
import { getConfig } from "@/lib/config";

afterEach(() => vi.unstubAllEnvs());

describe("input and request guards", () => {
  it("trims the identifier but preserves the exact password", () => {
    expect(loginInput.parse({ identifier: " DEV ", password: " p " }))
      .toEqual({ identifier: "dev", password: " p " });
  });
  it.each([
    { identifier: "", password: "x" },
    { identifier: "dev", password: "" },
    { identifier: "a".repeat(255), password: "x" },
    { identifier: "dev", password: "a".repeat(1025) },
    { identifier: "dev\nname", password: "x" },
    { identifier: "dev", password: "x", connection: "devdb" },
    { identifier: "dev@example.com", password: "x" },
    { identifier: "a".repeat(129), password: "x" },
  ])("rejects invalid input %j", (input) => {
    expect(loginInput.safeParse(input).success).toBe(false);
  });
  it("validates signup with recovery email and normalizes input", () => {
    expect(signupInput.parse({ username: " Dev.User ", email: " Dev@Example.com ", password: " password ", connection: "devdb" }))
      .toEqual({ username: "dev.user", email: "dev@example.com", password: " password ", connection: "devdb" });
    expect(signupInput.safeParse({ username: "dev", password: "password", connection: "devdb" }).success).toBe(false);
    expect(signupInput.safeParse({ username: "dev", email: "nope", password: "password", connection: "devdb" }).success).toBe(false);
    expect(signupInput.safeParse({ username: "dev", email: "dev@example.com", password: "short", connection: "devdb" }).success).toBe(false);
  });
  it("rejects oversized JSON even without a content-length header", async () => {
    const request = new Request("http://localhost:3000/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: "a".repeat(8192) }),
    });
    await expect(readSmallJson(request)).rejects.toThrow("Body too large");
  });
  it("rejects invalid JSON", async () => {
    const request = new Request("http://localhost:3000", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{",
    });
    await expect(readSmallJson(request)).rejects.toThrow();
  });
  it("rejects non-JSON requests", async () => {
    await expect(readSmallJson(new Request("http://localhost:3000", {
      method: "POST", body: "abc",
    }))).rejects.toThrow("Expected JSON");
  });
  it("uses the configured origin, not attacker-controlled host headers", () => {
    vi.stubEnv("AUTH0_DOMAIN", "lab.example.com");
    for (const name of ["AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_MANAGEMENT_CLIENT_ID", "AUTH0_MANAGEMENT_CLIENT_SECRET"]) {
      vi.stubEnv(name, "test-value");
    }
    vi.stubEnv("SESSION_SECRET", "x".repeat(32));
    vi.stubEnv("APP_ORIGIN", "http://localhost:3000");
    expect(sameOrigin(new Request("http://evil.example", {
      headers: { origin: "http://evil.example", host: "evil.example" },
    }))).toBe(false);
    expect(sameOrigin(new Request("http://localhost:3000"))).toBe(false);
    expect(sameOrigin(new Request("http://localhost:3000", {
      headers: { origin: "http://localhost:3000" },
    }))).toBe(true);
    vi.stubEnv("NODE_ENV", "production");
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => getConfig()).toThrow("APP_ORIGIN");
  });
});

describe("local rate limits", () => {
  it("allows 10 attempts, blocks the 11th, and expires at five minutes", () => {
    const allow = createLoginLimiter();
    for (let i = 0; i < 10; i++) expect(allow("dev@example.com", 0)).toBe(true);
    expect(allow("DEV@example.com", 1)).toBe(false);
    expect(allow("ecom@example.com", 1)).toBe(true);
    expect(allow("dev@example.com", 300_000)).toBe(true);
  });
  it("limits the whole process to 60 attempts/minute", () => {
    const allow = createLoginLimiter();
    for (let i = 0; i < 60; i++) expect(allow(`user${i}`, 0)).toBe(true);
    expect(allow("new-user", 1)).toBe(false);
    expect(allow("new-user", 60_000)).toBe(true);
  });
});

describe("session", () => {
  const user = { sub: "auth0|123", name: "Lab", username: "lab", connection: "devdb", expiresAt: 1 };
  it("rejects expired and absent profiles", () => {
    expect(activeUser(undefined)).toBeUndefined();
    expect(activeUser(user)).toBeUndefined();
    expect(activeUser({ ...user, expiresAt: Date.now() / 1000 + 60 })).toBeDefined();
  });
  it("encrypts profiles and rejects cookie tampering and wrong secrets", async () => {
    const password = "x".repeat(32);
    const sealed = await sealData({ user }, { password, ttl: 3600 });
    expect(sealed).not.toContain("auth0|123");
    expect(await unsealData(sealed, { password, ttl: 3600 })).toEqual({ user });
    expect(await unsealData(`${sealed.slice(0, 50)}X${sealed.slice(51)}`, { password, ttl: 3600 })).toEqual({});
    expect(await unsealData(sealed, { password: "y".repeat(32), ttl: 3600 })).toEqual({});
  });
});
