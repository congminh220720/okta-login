import { z } from "zod";

export const usernameInput = z.string().trim().toLowerCase().min(1).max(128)
  .regex(/^[a-z0-9._-]+$/, "Use letters, numbers, dots, underscores or hyphens (no email).");

export const loginInput = z.object({
  identifier: usernameInput,
  password: z.string().min(1).max(1024),
}).strict();

export const signupInput = z.object({
  username: usernameInput,
  email: z.string().trim().toLowerCase().max(254).pipe(z.email()),
  password: z.string().min(8).max(1024),
  connection: z.string().min(1).max(128),
}).strict();

export const forgotPasswordInput = z.object({ username: usernameInput }).strict();
