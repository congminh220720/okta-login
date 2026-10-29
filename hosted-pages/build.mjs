import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const outfile = `${root}dist/hosted-login.js`;

function appOrigin() {
  const value = process.env.HOSTED_APP_ORIGIN ?? "http://localhost:5173";
  const url = new URL(value);
  if (url.origin !== value || !["https:", "http:"].includes(url.protocol)) {
    throw new Error(`HOSTED_APP_ORIGIN must be an origin like https://app.example.com (got ${value})`);
  }
  return value;
}

await mkdir(`${root}dist`, { recursive: true });
await build({
  entryPoints: [`${root}src/index.ts`],
  bundle: true,
  minify: true,
  format: "iife",
  target: ["es2019"],
  legalComments: "none",
  outfile,
});

const contents = await readFile(outfile);
const hash = createHash("sha256").update(contents).digest("hex").slice(0, 8);
const versioned = `hosted-login.${hash}.js`;
await copyFile(outfile, `${root}dist/${versioned}`);
const integrity = `sha384-${createHash("sha384").update(contents).digest("base64")}`;
await writeFile(`${root}dist/manifest.json`, `${JSON.stringify({ file: versioned, integrity, bytes: contents.length }, null, 2)}\n`);

console.log(`Built hosted-pages/dist/${versioned} (${contents.length} bytes)`);
console.log(`integrity="${integrity}"`);

// Self-contained page: same template with the bundle inlined, ready to paste into Auth0.
const bundle = contents.toString("utf8");
if (/<\/script/i.test(bundle) || bundle.includes("@@")) {
  throw new Error("Bundle cannot be inlined safely into the Auth0 HTML template.");
}
const template = (await readFile(`${root}auth0-login-page.html`, "utf8"))
  // HOSTED_APP_ORIGIN=https://your-app.run.app npm run build:hosted -> URLs point to the deployed app.
  .replaceAll("http://localhost:5173", appOrigin());
const bucketTag = /[ \t]*<!-- EDIT 1:[^\n]*\n[ \t]*<script src="https:\/\/storage\.googleapis\.com\/[^"]*"><\/script>\n/;
if (!bucketTag.test(template)) throw new Error("Bucket <script> tag not found in auth0-login-page.html");
const inline = template
  .replace("2. Replace the editor contents with this file, then edit the three values marked EDIT.",
    "2. Replace the editor contents with this file (bundle inlined; no bucket needed), then check EDIT 2 and EDIT 3.")
  .replace(bucketTag, () => `  <!-- hosted-login bundle inlined by \`npm run build:hosted\` (${versioned}) -->\n  <script>${bundle}</script>\n`);
await writeFile(`${root}dist/auth0-login-page.inline.html`, inline);
console.log(`Built hosted-pages/dist/auth0-login-page.inline.html (${Buffer.byteLength(inline)} bytes)`);

// Password Reset page: same lab styles, Auth0's change-password widget does the actual reset.
const stylesBuild = await build({
  entryPoints: [`${root}src/styles.ts`], bundle: true, format: "esm", write: false, logLevel: "silent",
});
const { styles } = await import(`data:text/javascript;base64,${Buffer.from(stylesBuild.outputFiles[0].text).toString("base64")}`);
// Auth0 renders this page with Liquid: lab CSS must not contain Liquid delimiters.
if (/\{\{|\{%/.test(styles)) throw new Error("Lab styles contain Liquid delimiters");
const resetTemplate = await readFile(`${root}auth0-password-reset-page.html`, "utf8");
if (!resetTemplate.includes("/*__LAB_STYLES__*/")) throw new Error("Style placeholder missing in reset template");
const allowedLiquid = new Set(["email", "email | escape", "csrf_token", "ticket", "password_policy",
  "tenant.picture_url | default: '//cdn.auth0.com/styleguide/1.0.0/img/badge.png'"]);
for (const [, tag] of resetTemplate.matchAll(/\{\{\s*([^}]*?)\s*\}\}/g)) {
  if (!allowedLiquid.has(tag)) throw new Error(`Unexpected Liquid tag in reset template: {{${tag}}}`);
}
const resetPage = resetTemplate.replace("/*__LAB_STYLES__*/", () => styles.trim());
await writeFile(`${root}dist/auth0-password-reset-page.html`, resetPage);
console.log(`Built hosted-pages/dist/auth0-password-reset-page.html (${Buffer.byteLength(resetPage)} bytes)`);
