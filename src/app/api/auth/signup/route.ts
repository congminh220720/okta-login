import { AuthError, signup, SignupError } from "@/lib/auth0";
import { getConfig } from "@/lib/config";
import { json, readSmallJson, sameOrigin } from "@/lib/http";
import { signupInput } from "@/lib/login-input";
import { allowSignup } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
    let body: unknown;
    try {
      body = await readSmallJson(request);
    } catch {
      return json({ error: "Send a valid JSON signup request (maximum 8 KB)." }, 400);
    }
    const input = signupInput.safeParse(body);
    if (!input.success) {
      return json({ error: "Use a username with letters, numbers, dots, underscores or hyphens, a valid email address (used only for password reset), a password of 8-1024 characters, and a database connection." }, 400);
    }
    const config = getConfig();
    if (![config.AUTH0_DEV_CONNECTION, config.AUTH0_ECOM_CONNECTION].includes(input.data.connection)) {
      return json({ error: "Select one of the configured database connections." }, 400);
    }
    if (!allowSignup(input.data.username)) {
      return json({ error: "Too many signup attempts. Please wait 5 minutes and try again." }, 429);
    }
    await signup(input.data.username, input.data.password, input.data.connection, input.data.email);
    return json({ ok: true }, 201);
  } catch (error) {
    if (error instanceof SignupError) {
      const messages = {
        username_unavailable: "This username or email is already registered, or a signup is already in progress. Use different details or sign in.",
        signup_rejected: "Auth0 rejected signup. Check the connection's username length, email and password policy settings.",
        email_required: "Auth0 requires an email for the selected database connection. Enter a valid email address.",
        username_not_enabled: "Auth0 does not allow username for the selected database connection. Enable the Username attribute for signup and login in that connection.",
        password_policy: "Auth0 rejected the password because it does not satisfy the selected database's password policy. Choose a different password that meets the configured policy.",
        connection_disabled: "The selected database connection is not enabled for this app in Auth0. In Authentication > Database > (connection) > Applications, enable both the Machine to Machine app and the Regular Web App.",
        username_length: "This username is too long or too short for the selected database (Auth0 default: 1-15 characters). Choose a shorter username, or raise the limit in the connection's Username attribute settings.",
        invalid_connection: "Select one of the configured database connections.",
      };
      return json({ error: messages[error.code], code: error.code }, error.status);
    }
    if (error instanceof AuthError) {
      return json({ error: "Could not confirm account creation. Check Auth0 configuration, M2M read:users/create:users permissions and server logs. Creation may have completed: try signing in before submitting again." }, 503);
    }
    console.error("[signup] Internal error; check server configuration");
    return json({ error: "Server configuration error. Check .env.local and server logs." }, 500);
  }
}
