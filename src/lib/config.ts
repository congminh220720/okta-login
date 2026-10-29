import "server-only";
import { z } from "zod";

const configSchema = z.object({
  AUTH0_DOMAIN: z.string().regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}$/i),
  AUTH0_CLIENT_ID: z.string().min(1),
  AUTH0_CLIENT_SECRET: z.string().min(1),
  AUTH0_MANAGEMENT_CLIENT_ID: z.string().min(1),
  AUTH0_MANAGEMENT_CLIENT_SECRET: z.string().min(1),
  AUTH0_DEV_CONNECTION: z.string().min(1).default("devdb"),
  AUTH0_ECOM_CONNECTION: z.string().min(1).default("ecomdb"),
  SESSION_SECRET: z.string().min(32),
  // Comma-separated HTTPS origins of the Auth0-hosted login page (tenant or custom domain).
  AUTH0_LOGIN_PAGE_ORIGINS: z.string().optional(),
  APP_ORIGIN: z.url().refine((value) => {
    const url = new URL(value);
    return value === url.origin && (url.protocol === "https:" ||
      (process.env.NODE_ENV !== "production" && url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)));
  }, "Use an exact HTTPS origin (HTTP localhost is allowed in development)."),
}).refine((value) => value.AUTH0_DEV_CONNECTION !== value.AUTH0_ECOM_CONNECTION, {
  message: "Database connection names must be different.",
  path: ["AUTH0_ECOM_CONNECTION"],
});

export type Config = z.infer<typeof configSchema>;

export function loginPageOrigins(config: Config): string[] {
  const configured = config.AUTH0_LOGIN_PAGE_ORIGINS?.split(",").map((value) => value.trim()).filter(Boolean);
  const origins = configured?.length ? configured : [`https://${config.AUTH0_DOMAIN}`];
  return origins.filter((value) => {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.origin === value;
    } catch {
      return false;
    }
  });
}

export function getConfig(): Config {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    const fields = result.error.issues.map((issue) => issue.path.join(".")).join(", ");
    console.error("[config] Missing or invalid environment variables:", fields);
    throw new Error(`Invalid server configuration: ${fields}. Check .env.local.`);
  }
  return result.data;
}
