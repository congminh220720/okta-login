import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError } from "@/lib/auth0";

const mocks = vi.hoisted(() => ({
  resolveConnection: vi.fn(),
  allowResolve: vi.fn(),
  config: {
    AUTH0_DOMAIN: "lab.example.com",
    AUTH0_LOGIN_PAGE_ORIGINS: undefined as string | undefined,
  },
}));
vi.mock("@/lib/auth0", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/auth0")>(),
  resolveConnection: mocks.resolveConnection,
}));
vi.mock("@/lib/config", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/config")>(),
  getConfig: () => mocks.config,
}));
vi.mock("@/lib/rate-limit", () => ({ allowResolve: mocks.allowResolve }));

import { OPTIONS, POST } from "@/app/api/auth/resolve-connection/route";

const tenant = "https://lab.example.com";
function request(body: unknown = { username: "DevUser" }, origin: string | null = tenant) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (origin) headers.Origin = origin;
  return new Request("http://localhost:5173/api/auth/resolve-connection", {
    method: "POST", headers, body: JSON.stringify(body),
  });
}

beforeEach(() => {
  mocks.config.AUTH0_LOGIN_PAGE_ORIGINS = undefined;
  mocks.allowResolve.mockReturnValue(true);
  mocks.resolveConnection.mockResolvedValue("ecomdb");
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("resolve-connection route", () => {
  it("returns the connection to the Auth0 tenant origin with CORS headers", async () => {
    const response = await POST(request());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ connection: "ecomdb" });
    expect(response.headers.get("access-control-allow-origin")).toBe(tenant);
    expect(response.headers.get("vary")).toBe("Origin");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mocks.resolveConnection).toHaveBeenCalledWith("devuser");
  });

  it.each([null, "https://evil.example", "http://lab.example.com", "http://localhost:5173"])(
    "rejects origin %s before lookup", async (origin) => {
      const response = await POST(request(undefined, origin));
      expect(response.status).toBe(403);
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      expect(mocks.resolveConnection).not.toHaveBeenCalled();
    },
  );

  it("supports configured custom-domain origins and ignores invalid entries", async () => {
    mocks.config.AUTH0_LOGIN_PAGE_ORIGINS = "https://login.example.com, http://insecure.example, not-a-url";
    expect((await POST(request(undefined, "https://login.example.com"))).status).toBe(200);
    expect((await POST(request(undefined, "http://insecure.example"))).status).toBe(403);
    expect((await POST(request(undefined, tenant))).status).toBe(403);
  });

  it.each([{ username: "dev@example.com" }, { username: "dev", password: "x" }, {}])(
    "rejects invalid input %j", async (body) => {
      expect((await POST(request(body))).status).toBe(400);
      expect(mocks.resolveConnection).not.toHaveBeenCalled();
    },
  );

  it("returns 404 when no single database identity matches", async () => {
    mocks.resolveConnection.mockResolvedValue(undefined);
    const response = await POST(request());
    expect(response.status).toBe(404);
    expect(response.headers.get("access-control-allow-origin")).toBe(tenant);
  });

  it("rate limits before lookup", async () => {
    mocks.allowResolve.mockReturnValue(false);
    expect((await POST(request())).status).toBe(429);
    expect(mocks.resolveConnection).not.toHaveBeenCalled();
  });

  it("reports Auth0 failures as 503", async () => {
    mocks.resolveConnection.mockRejectedValue(new AuthError("provider_unavailable", 503));
    expect((await POST(request())).status).toBe(503);
  });

  it("answers allowed preflight including Chrome local network access", async () => {
    const response = await OPTIONS(new Request("http://localhost:5173/api/auth/resolve-connection", {
      method: "OPTIONS",
      headers: { Origin: tenant, "Access-Control-Request-Private-Network": "true" },
    }));
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(tenant);
    expect(response.headers.get("access-control-allow-methods")).toContain("POST");
    expect(response.headers.get("access-control-allow-private-network")).toBe("true");
  });

  it("rejects preflight from other origins", async () => {
    const response = await OPTIONS(new Request("http://localhost:5173/api/auth/resolve-connection", {
      method: "OPTIONS", headers: { Origin: "https://evil.example" },
    }));
    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });
});
