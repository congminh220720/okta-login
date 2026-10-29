import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError } from "@/lib/auth0";

const mocks = vi.hoisted(() => ({
  requestPasswordReset: vi.fn(),
  allowPasswordReset: vi.fn(),
}));
vi.mock("@/lib/auth0", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/auth0")>(),
  requestPasswordReset: mocks.requestPasswordReset,
}));
vi.mock("@/lib/config", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/config")>(),
  getConfig: () => ({ AUTH0_DOMAIN: "lab.example.com" }),
}));
vi.mock("@/lib/rate-limit", () => ({ allowPasswordReset: mocks.allowPasswordReset }));

import { OPTIONS, POST } from "@/app/api/auth/forgot-password/route";

const tenant = "https://lab.example.com";
function request(body: unknown = { username: "DevUser" }, origin: string | null = tenant) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (origin) headers.Origin = origin;
  return new Request("http://localhost:5173/api/auth/forgot-password", { method: "POST", headers, body: JSON.stringify(body) });
}

beforeEach(() => {
  mocks.allowPasswordReset.mockReturnValue(true);
  mocks.requestPasswordReset.mockResolvedValue(undefined);
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("forgot-password route", () => {
  it("asks Auth0 to send a reset link and returns a generic message with CORS", async () => {
    const response = await POST(request());
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ ok: true });
    expect(JSON.stringify(body)).not.toMatch(/@|devdb|ecomdb/);
    expect(response.headers.get("access-control-allow-origin")).toBe(tenant);
    expect(mocks.requestPasswordReset).toHaveBeenCalledWith("devuser");
  });

  it.each([null, "https://evil.example", "http://localhost:5173"])("rejects origin %s", async (origin) => {
    expect((await POST(request(undefined, origin))).status).toBe(403);
    expect(mocks.requestPasswordReset).not.toHaveBeenCalled();
  });

  it.each([{ username: "dev@example.com" }, { username: "dev", email: "x@example.com" }, {}])(
    "rejects invalid input %j", async (body) => {
      expect((await POST(request(body))).status).toBe(400);
      expect(mocks.requestPasswordReset).not.toHaveBeenCalled();
    },
  );

  it("rate limits before contacting Auth0", async () => {
    mocks.allowPasswordReset.mockReturnValue(false);
    expect((await POST(request())).status).toBe(429);
    expect(mocks.requestPasswordReset).not.toHaveBeenCalled();
  });

  it("reports Auth0 failures as 503", async () => {
    mocks.requestPasswordReset.mockRejectedValue(new AuthError("provider_unavailable", 503));
    expect((await POST(request())).status).toBe(503);
  });

  it("answers preflight for the Auth0 origin only", async () => {
    const ok = OPTIONS(new Request("http://localhost:5173/api/auth/forgot-password", {
      method: "OPTIONS", headers: { Origin: tenant },
    }));
    expect(ok.status).toBe(204);
    const bad = OPTIONS(new Request("http://localhost:5173/api/auth/forgot-password", {
      method: "OPTIONS", headers: { Origin: "https://evil.example" },
    }));
    expect(bad.status).toBe(403);
  });
});
