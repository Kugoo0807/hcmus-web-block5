import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { importJWK, SignJWT } from "jose";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const ACCESS_TOKEN_TTL_SECONDS = 120;
const AUTH_CODE_TTL_SECONDS = 60;
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error("Missing required environment variable: " + name);
  return value;
}
function fromB64Json(name) {
  try { return JSON.parse(Buffer.from(required(name), "base64url").toString("utf8")); }
  catch { throw new Error(name + " must be base64url-encoded JSON"); }
}
const config = {
  baseUrl: required("WALLET_AS_BASE_URL"),
  apiBaseUrl: required("WALLET_API_BASE_URL"),
  taxiBaseUrl: required("TAXI_BASE_URL"),
  port: Number(process.env.WALLET_AS_PORT || 3001),
  kid: required("WALLET_AS_KID"),
  privateJwk: fromB64Json("WALLET_AS_PRIVATE_JWK_B64"),
  publicJwk: fromB64Json("WALLET_AS_PUBLIC_JWK_B64"),
  sessionSecret: required("WALLET_AS_SESSION_SECRET"),
  taxiWebSecret: required("TAXI_WEB_CLIENT_SECRET"),
  taxiM2mSecret: required("TAXI_M2M_CLIENT_SECRET"),
  dbPath: process.env.WALLET_AS_DB_PATH || resolve(root, "apps/wallet-as/data/wallet-as.sqlite")
};
const privateKey = await importJWK(config.privateJwk, "ES256");
mkdirSync(dirname(config.dbPath), { recursive: true });
const db = new DatabaseSync(config.dbPath);
db.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;");

function now() { return new Date().toISOString(); }
function future(seconds) { return new Date(Date.now() + seconds * 1000).toISOString(); }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function base64UrlSha256(value) { return createHash("sha256").update(value).digest("base64url"); }
function randomToken() { return randomBytes(32).toString("base64url"); }
function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left)); const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}
function splitScope(value) {
  if (typeof value !== "string" || value.trim() === "") return [];
  return [...new Set(value.trim().split(/\s+/))];
}
function parseStoredScope(value) { return JSON.parse(value); }
function includesEvery(allowed, requested) { return requested.every(function (scope) { return allowed.includes(scope); }); }
function isExpired(isoTime) { return new Date(isoTime).getTime() <= Date.now(); }
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, function (char) {
    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char];
  });
}
function page(title, body) {
  return [
    "<!doctype html><html lang='vi'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
    "<title>" + escapeHtml(title) + "</title>",
    "<style>body{font-family:system-ui,sans-serif;background:#f6f7fb;color:#172033;margin:0}.wrap{max-width:720px;margin:48px auto;padding:0 20px}.card{background:#fff;border:1px solid #dce1eb;border-radius:12px;padding:28px;box-shadow:0 8px 26px #1d2c4a12}h1{margin-top:0}label{display:block;margin:14px 0 6px;font-weight:600}input{box-sizing:border-box;width:100%;padding:10px;border:1px solid #b7c1d2;border-radius:7px}button,.button{display:inline-block;margin-top:18px;padding:10px 15px;border:0;border-radius:7px;background:#225ad5;color:#fff;font-weight:700;text-decoration:none;cursor:pointer}.secondary{background:#606b7e}.danger{background:#b92638}.notice{padding:12px;background:#e8f0ff;border-radius:7px}.error{padding:12px;background:#ffe7e9;color:#8c1324;border-radius:7px}code{background:#eef1f6;padding:2px 5px;border-radius:4px}ul{padding-left:20px}</style></head><body><main class='wrap'><section class='card'>",
    body, "</section></main></body></html>"
  ].join("");
}
function sendAsError(res, status, title, message) {
  return res.status(status).send(page(title, "<h1>" + escapeHtml(title) + "</h1><p class='error'>" + escapeHtml(message) + "</p>"));
}
function appendParams(rawUrl, params) {
  const target = new URL(rawUrl);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== "") target.searchParams.set(key, value);
  return target.toString();
}
class OAuthFailure extends Error {
  constructor(error, status, description) { super(description || error); this.error = error; this.status = status || 400; }
}
function sendTokenError(res, failure) {
  if (failure.error === "invalid_client") res.set("WWW-Authenticate", 'Basic realm="wallet-as"');
  return res.status(failure.status).json({ error: failure.error, error_description: failure.message });
}

function initializeSchema() {
  db.exec([
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, redirect_uri TEXT NOT NULL, allowed_scopes TEXT NOT NULL, allowed_grants TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS consents (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id), scope TEXT NOT NULL, granted_at TEXT NOT NULL, revoked_at TEXT, UNIQUE(user_id, client_id));",
    "CREATE TABLE IF NOT EXISTS auth_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL UNIQUE, client_id TEXT NOT NULL REFERENCES clients(id), redirect_uri TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), scope TEXT NOT NULL, code_challenge TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);",
    "CREATE TABLE IF NOT EXISTS refresh_tokens (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, family_id TEXT NOT NULL, client_id TEXT NOT NULL REFERENCES clients(id), user_id INTEGER NOT NULL REFERENCES users(id), scope TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, revoked_at TEXT, replaced_by TEXT);",
    "CREATE TABLE IF NOT EXISTS access_tokens (jti TEXT PRIMARY KEY, code_id INTEGER, family_id TEXT, client_id TEXT NOT NULL REFERENCES clients(id), user_id INTEGER, expires_at TEXT NOT NULL, revoked_at TEXT);",
    "CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);",
    "CREATE INDEX IF NOT EXISTS idx_access_code ON access_tokens(code_id);"
  ].join("\n"));
}
async function seedDatabase() {
  const alice = await bcrypt.hash("alice-password", 12);
  const bob = await bcrypt.hash("bob-password", 12);
  const users = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash");
  users.run("alice", alice); users.run("bob", bob);
  const taxiWeb = await bcrypt.hash(config.taxiWebSecret, 12);
  const taxiM2m = await bcrypt.hash(config.taxiM2mSecret, 12);
  const upsert = db.prepare("INSERT INTO clients (id, secret_hash, redirect_uri, allowed_scopes, allowed_grants) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET secret_hash = excluded.secret_hash, redirect_uri = excluded.redirect_uri, allowed_scopes = excluded.allowed_scopes, allowed_grants = excluded.allowed_grants");
  upsert.run("taxi-web", taxiWeb, config.taxiBaseUrl + "/oauth/callback", JSON.stringify(["wallet:read", "wallet:charge", "offline_access"]), JSON.stringify(["authorization_code", "refresh_token"]));
  upsert.run("taxi-m2m", taxiM2m, config.taxiBaseUrl + "/machine/callback", JSON.stringify(["rates:read"]), JSON.stringify(["client_credentials"]));
}
function getClient(id) { return db.prepare("SELECT * FROM clients WHERE id = ?").get(id); }

function validateAuthorizationRequest(query) {
  const clientId = typeof query.client_id === "string" ? query.client_id : "";
  const client = clientId ? getClient(clientId) : undefined;
  if (!client) return { asError: ["Invalid authorization request", "Unknown client_id. No redirect was attempted."] };
  const redirectUri = typeof query.redirect_uri === "string" ? query.redirect_uri : "";
  if (redirectUri !== client.redirect_uri) return { asError: ["Invalid authorization request", "redirect_uri does not exactly match the registered value. No redirect was attempted."] };
  const state = typeof query.state === "string" ? query.state : undefined;
  if (query.response_type !== "code") return { client, redirectUri, state, redirectError: "invalid_request", redirectDescription: "response_type must be code" };
  const scopes = splitScope(query.scope);
  if (scopes.length === 0 || !includesEvery(parseStoredScope(client.allowed_scopes), scopes)) return { client, redirectUri, state, redirectError: "invalid_scope", redirectDescription: "Requested scope is not allowed for this client" };
  const challenge = typeof query.code_challenge === "string" ? query.code_challenge : "";
  if (!challenge || query.code_challenge_method !== "S256") return { client, redirectUri, state, redirectError: "invalid_request", redirectDescription: "PKCE S256 code_challenge is required" };
  return { client, redirectUri, state, scopes, codeChallenge: challenge };
}
function redirectOAuthError(res, authorization, error, description) {
  return res.redirect(302, appendParams(authorization.redirectUri, { error, error_description: description, state: authorization.state }));
}
async function createAccessToken(values) {
  const jti = randomToken();
  const token = await new SignJWT({ client_id: values.clientId, scope: values.scopes.join(" "), principal_type: values.principalType })
    .setProtectedHeader({ alg: "ES256", kid: config.kid, typ: "at+jwt" }).setIssuer(config.baseUrl).setAudience("wallet-api")
    .setSubject(String(values.subject)).setJti(jti).setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECONDS).sign(privateKey);
  return { token, jti, expiresAt: future(ACCESS_TOKEN_TTL_SECONDS) };
}

async function issueForAuthorizationCode(client, body) {
  const code = typeof body.code === "string" ? body.code : "";
  const redirectUri = typeof body.redirect_uri === "string" ? body.redirect_uri : "";
  const verifier = typeof body.code_verifier === "string" ? body.code_verifier : "";
  if (!code || !redirectUri || !verifier) throw new OAuthFailure("invalid_request", 400, "code, redirect_uri, and code_verifier are required");
  const initial = db.prepare("SELECT * FROM auth_codes WHERE code_hash = ?").get(sha256(code));
  if (!initial) throw new OAuthFailure("invalid_grant", 400, "Authorization code is invalid");
  if (initial.used_at) {
    db.exec("BEGIN IMMEDIATE"); try { db.prepare("UPDATE access_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE code_id = ?").run(now(), initial.id); db.exec("COMMIT"); } catch (error) { db.exec("ROLLBACK"); throw error; }
    throw new OAuthFailure("invalid_grant", 400, "Authorization code has already been used");
  }
  if (isExpired(initial.expires_at) || initial.client_id !== client.id || initial.redirect_uri !== redirectUri || !constantTimeEqual(base64UrlSha256(verifier), initial.code_challenge)) throw new OAuthFailure("invalid_grant", 400, "Authorization code validation failed");
  const scopes = parseStoredScope(initial.scope);
  const access = await createAccessToken({ clientId: client.id, subject: initial.user_id, scopes, principalType: "user" });
  const includeRefresh = scopes.includes("offline_access");
  const rawRefresh = includeRefresh ? randomToken() : null;
  const refreshId = includeRefresh ? randomToken() : null;
  const familyId = includeRefresh ? randomToken() : null;
  db.exec("BEGIN IMMEDIATE");
  try {
    const current = db.prepare("SELECT * FROM auth_codes WHERE id = ?").get(initial.id);
    if (!current || current.used_at || isExpired(current.expires_at) || current.client_id !== client.id || current.redirect_uri !== redirectUri || !constantTimeEqual(base64UrlSha256(verifier), current.code_challenge)) throw new OAuthFailure("invalid_grant", 400, "Authorization code validation failed");
    db.prepare("UPDATE auth_codes SET used_at = ? WHERE id = ?").run(now(), current.id);
    db.prepare("INSERT INTO access_tokens (jti, code_id, family_id, client_id, user_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)").run(access.jti, current.id, familyId, client.id, current.user_id, access.expiresAt);
    if (rawRefresh) db.prepare("INSERT INTO refresh_tokens (id, token_hash, family_id, client_id, user_id, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(refreshId, sha256(rawRefresh), familyId, client.id, current.user_id, current.scope, now(), future(REFRESH_TOKEN_TTL_SECONDS));
    db.exec("COMMIT");
  } catch (error) { db.exec("ROLLBACK"); throw error; }
  const response = { access_token: access.token, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_SECONDS, scope: scopes.join(" ") };
  if (rawRefresh) response.refresh_token = rawRefresh;
  return response;
}

async function issueForRefreshToken(client, body) {
  const rawRefresh = typeof body.refresh_token === "string" ? body.refresh_token : "";
  if (!rawRefresh) throw new OAuthFailure("invalid_request", 400, "refresh_token is required");
  const initial = db.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?").get(sha256(rawRefresh));
  if (!initial) throw new OAuthFailure("invalid_grant", 400, "Refresh token is invalid");
  const originalScopes = parseStoredScope(initial.scope);
  const requestedScopes = body.scope ? splitScope(body.scope) : originalScopes;
  if (!includesEvery(originalScopes, requestedScopes)) throw new OAuthFailure("invalid_scope", 400, "Requested scope exceeds the grant");
  if (initial.used_at) {
    db.exec("BEGIN IMMEDIATE"); try { db.prepare("UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?").run(now(), initial.family_id); db.exec("COMMIT"); } catch (error) { db.exec("ROLLBACK"); throw error; }
    throw new OAuthFailure("invalid_grant", 400, "Refresh token replay detected; the token family was revoked");
  }
  if (initial.client_id !== client.id || initial.revoked_at || isExpired(initial.expires_at)) throw new OAuthFailure("invalid_grant", 400, "Refresh token validation failed");
  const consent = db.prepare("SELECT * FROM consents WHERE user_id = ? AND client_id = ?").get(initial.user_id, client.id);
  if (!consent || consent.revoked_at) throw new OAuthFailure("invalid_grant", 400, "Consent is no longer active");
  const access = await createAccessToken({ clientId: client.id, subject: initial.user_id, scopes: requestedScopes, principalType: "user" });
  const replacementRaw = randomToken(); const replacementId = randomToken();
  db.exec("BEGIN IMMEDIATE");
  try {
    const current = db.prepare("SELECT * FROM refresh_tokens WHERE id = ?").get(initial.id);
    const activeConsent = db.prepare("SELECT * FROM consents WHERE user_id = ? AND client_id = ?").get(initial.user_id, client.id);
    if (!current || current.used_at || current.client_id !== client.id || current.revoked_at || isExpired(current.expires_at) || !activeConsent || activeConsent.revoked_at) throw new OAuthFailure("invalid_grant", 400, "Refresh token validation failed");
    db.prepare("INSERT INTO refresh_tokens (id, token_hash, family_id, client_id, user_id, scope, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(replacementId, sha256(replacementRaw), current.family_id, client.id, current.user_id, JSON.stringify(requestedScopes), now(), future(REFRESH_TOKEN_TTL_SECONDS));
    db.prepare("UPDATE refresh_tokens SET used_at = ?, replaced_by = ? WHERE id = ?").run(now(), replacementId, current.id);
    db.prepare("INSERT INTO access_tokens (jti, family_id, client_id, user_id, expires_at) VALUES (?, ?, ?, ?, ?)").run(access.jti, current.family_id, client.id, current.user_id, access.expiresAt);
    db.exec("COMMIT");
  } catch (error) { db.exec("ROLLBACK"); throw error; }
  return { access_token: access.token, refresh_token: replacementRaw, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_SECONDS, scope: requestedScopes.join(" ") };
}
async function issueForClientCredentials(client, body) {
  const requestedScopes = body.scope ? splitScope(body.scope) : parseStoredScope(client.allowed_scopes);
  if (requestedScopes.length === 0 || !includesEvery(parseStoredScope(client.allowed_scopes), requestedScopes)) throw new OAuthFailure("invalid_scope", 400, "Requested scope is not allowed for this client");
  const access = await createAccessToken({ clientId: client.id, subject: client.id, scopes: requestedScopes, principalType: "client" });
  db.prepare("INSERT INTO access_tokens (jti, client_id, expires_at) VALUES (?, ?, ?)").run(access.jti, client.id, access.expiresAt);
  return { access_token: access.token, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_SECONDS, scope: requestedScopes.join(" ") };
}
async function authenticateClient(req) {
  const header = req.get("authorization") || "";
  if (!header.startsWith("Basic ")) throw new OAuthFailure("invalid_client", 401, "HTTP Basic client authentication is required");
  let decoded; try { decoded = Buffer.from(header.slice(6), "base64").toString("utf8"); } catch { throw new OAuthFailure("invalid_client", 401, "Client authentication failed"); }
  const separator = decoded.indexOf(":");
  if (separator < 1) throw new OAuthFailure("invalid_client", 401, "Client authentication failed");
  const client = getClient(decoded.slice(0, separator));
  if (!client || !(await bcrypt.compare(decoded.slice(separator + 1), client.secret_hash))) throw new OAuthFailure("invalid_client", 401, "Client authentication failed");
  return client;
}

const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(session({ name: "wallet_as_session", secret: config.sessionSecret, resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 20 * 60 * 1000 } }));
app.get("/health", function (_req, res) { res.json({ service: "wallet-as", status: "ok" }); });
app.get("/.well-known/openid-configuration", function (_req, res) {
  res.json({ issuer: config.baseUrl, authorization_endpoint: config.baseUrl + "/authorize", token_endpoint: config.baseUrl + "/token", jwks_uri: config.baseUrl + "/.well-known/jwks.json", response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"], token_endpoint_auth_methods_supported: ["client_secret_basic"], code_challenge_methods_supported: ["S256"] });
});
app.get("/.well-known/jwks.json", function (_req, res) { res.set("Cache-Control", "public, max-age=300").json({ keys: [{ ...config.publicJwk, kid: config.kid, use: "sig", alg: "ES256" }] }); });

app.get("/authorize", function (req, res) {
  const authorization = validateAuthorizationRequest(req.query);
  if (authorization.asError) return sendAsError(res, 400, authorization.asError[0], authorization.asError[1]);
  if (authorization.redirectError) return redirectOAuthError(res, authorization, authorization.redirectError, authorization.redirectDescription);
  req.session.pendingAuthorization = authorization;
  if (!req.session.user) return res.redirect(302, "/login");
  return res.redirect(302, "/consent");
});
app.get("/login", function (req, res) {
  if (!req.session.pendingAuthorization) return sendAsError(res, 400, "No pending authorization", "Start again from the client application.");
  res.send(page("Wallet sign in", "<h1>Wallet sign in</h1><p>Sign in to decide whether Taxi may access your wallet.</p><form method='post' action='/login'><label>Username<input name='username' autocomplete='username' required></label><label>Password<input type='password' name='password' autocomplete='current-password' required></label><button type='submit'>Sign in</button></form><p><small>Lab users: alice / alice-password; bob / bob-password</small></p>"));
});
app.post("/login", async function (req, res, next) {
  try {
    if (!req.session.pendingAuthorization) return sendAsError(res, 400, "No pending authorization", "Start again from the client application.");
    const username = typeof req.body.username === "string" ? req.body.username : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).send(page("Wallet sign in", "<h1>Wallet sign in</h1><p class='error'>Invalid username or password.</p><a class='button secondary' href='/login'>Try again</a>"));
    req.session.user = { id: user.id, username: user.username };
    req.session.save(function (error) { if (error) return next(error); res.redirect(302, "/consent"); });
  } catch (error) { next(error); }
});
app.get("/consent", function (req, res) {
  const authorization = req.session.pendingAuthorization;
  if (!authorization || !req.session.user) return sendAsError(res, 400, "No pending authorization", "Start again from the client application.");
  const items = authorization.scopes.map(function (scope) { return "<li><code>" + escapeHtml(scope) + "</code></li>"; }).join("");
  res.send(page("Wallet consent", "<h1>Allow Taxi?</h1><p><strong>" + escapeHtml(req.session.user.username) + "</strong>, Taxi requests these permissions:</p><ul>" + items + "</ul><form method='post' action='/consent'><button name='decision' value='approve' type='submit'>Allow</button><button class='secondary' name='decision' value='deny' type='submit'>Deny</button></form><p><small>The browser receives only an authorization code; tokens go directly to Taxi server.</small></p>"));
});
app.post("/consent", function (req, res, next) {
  try {
    const authorization = req.session.pendingAuthorization; const user = req.session.user;
    if (!authorization || !user) return sendAsError(res, 400, "No pending authorization", "Start again from the client application.");
    delete req.session.pendingAuthorization;
    if (req.body.decision !== "approve") return redirectOAuthError(res, authorization, "access_denied", "The resource owner denied the request");
    const issuedAt = now();
    db.prepare("INSERT INTO consents (user_id, client_id, scope, granted_at, revoked_at) VALUES (?, ?, ?, ?, NULL) ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = excluded.granted_at, revoked_at = NULL").run(user.id, authorization.client.id, JSON.stringify(authorization.scopes), issuedAt);
    const rawCode = randomToken();
    db.prepare("INSERT INTO auth_codes (code_hash, client_id, redirect_uri, user_id, scope, code_challenge, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(sha256(rawCode), authorization.client.id, authorization.redirectUri, user.id, JSON.stringify(authorization.scopes), authorization.codeChallenge, issuedAt, future(AUTH_CODE_TTL_SECONDS));
    res.redirect(302, appendParams(authorization.redirectUri, { code: rawCode, state: authorization.state }));
  } catch (error) { next(error); }
});
app.get("/account", function (req, res) {
  if (!req.session.user) return res.redirect(302, "/login");
  const consents = db.prepare("SELECT client_id, scope, granted_at, revoked_at FROM consents WHERE user_id = ? ORDER BY granted_at DESC").all(req.session.user.id);
  const rows = consents.length ? consents.map(function (consent) {
    const action = consent.revoked_at ? "<em>Revoked</em>" : "<form method='post' action='/account/revoke'><input type='hidden' name='client_id' value='" + escapeHtml(consent.client_id) + "'><button class='danger' type='submit'>Revoke Taxi access</button></form>";
    return "<li><strong>" + escapeHtml(consent.client_id) + "</strong> — <code>" + escapeHtml(parseStoredScope(consent.scope).join(" ")) + "</code> " + action + "</li>";
  }).join("") : "<li>No connected clients.</li>";
  res.send(page("Wallet account", "<h1>Wallet account</h1><p>Signed in as <strong>" + escapeHtml(req.session.user.username) + "</strong>.</p><ul>" + rows + "</ul><p><small>Revoking consent revokes refresh-token families. Existing access tokens remain valid through exp because the API validates them offline, except tokens explicitly revoked after authorization-code replay.</small></p>"));
});
app.post("/account/revoke", function (req, res, next) {
  try {
    if (!req.session.user) return res.redirect(302, "/login");
    const clientId = typeof req.body.client_id === "string" ? req.body.client_id : "";
    if (!getClient(clientId)) return sendAsError(res, 400, "Invalid client", "Unknown client.");
    db.exec("BEGIN IMMEDIATE");
    try { const revokedAt = now(); db.prepare("UPDATE consents SET revoked_at = ? WHERE user_id = ? AND client_id = ?").run(revokedAt, req.session.user.id, clientId); db.prepare("UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ? AND client_id = ?").run(revokedAt, req.session.user.id, clientId); db.exec("COMMIT"); }
    catch (error) { db.exec("ROLLBACK"); throw error; }
    res.redirect(302, "/account");
  } catch (error) { next(error); }
});
app.post("/token", async function (req, res) {
  try {
    const client = await authenticateClient(req);
    const grantType = req.body.grant_type; let response;
    if (grantType === "authorization_code") { if (!parseStoredScope(client.allowed_grants).includes(grantType)) throw new OAuthFailure("unauthorized_client", 400, "Client is not allowed to use this grant"); response = await issueForAuthorizationCode(client, req.body); }
    else if (grantType === "refresh_token") { if (!parseStoredScope(client.allowed_grants).includes(grantType)) throw new OAuthFailure("unauthorized_client", 400, "Client is not allowed to use this grant"); response = await issueForRefreshToken(client, req.body); }
    else if (grantType === "client_credentials") { if (!parseStoredScope(client.allowed_grants).includes(grantType)) throw new OAuthFailure("unauthorized_client", 400, "Client is not allowed to use this grant"); response = await issueForClientCredentials(client, req.body); }
    else throw new OAuthFailure("unsupported_grant_type", 400, "Unsupported grant_type");
    res.set("Cache-Control", "no-store").json(response);
  } catch (error) {
    if (error instanceof OAuthFailure) return sendTokenError(res, error);
    console.error("token endpoint failed", error.message);
    return sendTokenError(res, new OAuthFailure("invalid_request", 400, "Request could not be processed"));
  }
});
app.get("/internal/revocations", function (_req, res) {
  const rows = db.prepare("SELECT jti FROM access_tokens WHERE revoked_at IS NOT NULL AND expires_at > ?").all(now());
  res.set("Cache-Control", "no-store").json({ revoked_jtis: rows.map(function (row) { return row.jti; }) });
});
app.use(function (error, _req, res, _next) {
  console.error("wallet-as request failed", error.message);
  if (!res.headersSent) sendAsError(res, 500, "Internal error", "The request could not be completed.");
});

initializeSchema();
await seedDatabase();
app.listen(config.port, "127.0.0.1", function () { console.log("Wallet AS listening on " + config.baseUrl); });
