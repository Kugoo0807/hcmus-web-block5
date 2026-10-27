import express from "express";
import session from "express-session";
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";
import { Issuer, generators } from "openid-client";
import { createRemoteJWKSet, jwtVerify } from "jose";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error("Missing required environment variable: " + name);
  return value;
}
const config = {
  baseUrl: required("TAXI_BASE_URL"),
  asBaseUrl: required("WALLET_AS_BASE_URL"),
  apiBaseUrl: required("WALLET_API_BASE_URL"),
  port: Number(process.env.TAXI_PORT || 3003),
  clientId: required("TAXI_WEB_CLIENT_ID"),
  clientSecret: required("TAXI_WEB_CLIENT_SECRET"),
  sessionSecret: required("TAXI_SESSION_SECRET"),
  jobKey: required("TAXI_JOB_KEY"),
  tokenKey: Buffer.from(required("TAXI_TOKEN_ENCRYPTION_KEY_B64"), "base64url"),
  dbPath: process.env.TAXI_DB_PATH || resolve(root, "apps/taxi/data/taxi.sqlite"),
  logDbPath: process.env.TAXI_LOG_DB_PATH || resolve(root, "apps/taxi/data/taxi-logs.sqlite")
};
if (config.tokenKey.length !== 32) throw new Error("TAXI_TOKEN_ENCRYPTION_KEY_B64 must decode to 32 bytes");
mkdirSync(dirname(config.dbPath), { recursive: true });
const tokenDb = new DatabaseSync(config.dbPath);
const logDb = new DatabaseSync(config.logDbPath);
tokenDb.exec("PRAGMA journal_mode = WAL; CREATE TABLE IF NOT EXISTS linked_wallets (user_id TEXT PRIMARY KEY, refresh_cipher TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL, connected_at TEXT NOT NULL, updated_at TEXT NOT NULL);");
logDb.exec("PRAGMA journal_mode = WAL; CREATE TABLE IF NOT EXISTS payment_logs (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);");

function now() { return new Date().toISOString(); }
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, function (char) {
    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char];
  });
}
function page(title, body) {
  return [
    "<!doctype html><html lang='vi'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>", escapeHtml(title), "</title>",
    "<style>body{font-family:system-ui,sans-serif;background:#f4f7fb;color:#18243b;margin:0}.wrap{max-width:840px;margin:44px auto;padding:0 20px}.card{background:#fff;border:1px solid #d9e1ee;border-radius:14px;padding:28px;margin-bottom:18px;box-shadow:0 10px 30px #22385b13}h1,h2{margin-top:0}button,.button{display:inline-block;background:#1559cc;color:white;border:0;border-radius:8px;padding:10px 16px;font-weight:700;text-decoration:none;cursor:pointer;margin:4px 6px 4px 0}.secondary{background:#58677c}.good{background:#e7f8ec;padding:11px;border-radius:8px}.warn{background:#fff0db;padding:11px;border-radius:8px}.error{background:#ffe6e9;padding:11px;border-radius:8px}code{background:#edf1f7;padding:2px 5px;border-radius:4px}.muted{color:#56657a}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e3e8f0;padding:8px;text-align:left}</style></head><body><main class='wrap'>", body, "</main></body></html>"
  ].join("");
}
function encrypt(secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", config.tokenKey, iv);
  const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, body].map(function (part) { return part.toString("base64url"); }).join(".");
}
function decrypt(serialized) {
  const pieces = String(serialized).split(".").map(function (piece) { return Buffer.from(piece, "base64url"); });
  if (pieces.length !== 3 || pieces[0].length !== 12 || pieces[1].length !== 16) throw new Error("Stored refresh token is malformed");
  const decipher = createDecipheriv("aes-256-gcm", config.tokenKey, pieces[0]);
  decipher.setAuthTag(pieces[1]);
  return Buffer.concat([decipher.update(pieces[2]), decipher.final()]).toString("utf8");
}
function logPayment(jobId, userId, status, details) {
  logDb.prepare("INSERT INTO payment_logs (id, job_id, user_id, status, details, created_at) VALUES (?, ?, ?, ?, ?, ?)").run("log_" + crypto.randomUUID(), jobId, userId, status, JSON.stringify(details), now());
}
function stableJobKey(userId) {
  const date = new Date().toISOString().slice(0, 10);
  return "daily-fare-" + userId + "-" + date;
}
const jwks = createRemoteJWKSet(new URL(config.asBaseUrl + "/.well-known/jwks.json"));
async function validateUserAccessToken(token) {
  const verified = await jwtVerify(token, jwks, { issuer: config.asBaseUrl, audience: "wallet-api", algorithms: ["ES256"] });
  const payload = verified.payload;
  if (payload.principal_type !== "user" || typeof payload.sub !== "string" || typeof payload.exp !== "number") throw new Error("AS returned an invalid user access token");
  return payload;
}

let oauthClientPromise;
function oauthClient() {
  if (!oauthClientPromise) {
    oauthClientPromise = Issuer.discover(config.asBaseUrl).then(function (issuer) {
      return new issuer.Client({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uris: [config.baseUrl + "/oauth/callback"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic"
      });
    });
  }
  return oauthClientPromise;
}
async function rotateRefreshToken(userId) {
  const record = tokenDb.prepare("SELECT * FROM linked_wallets WHERE user_id = ? AND status = 'linked'").get(userId);
  if (!record) throw new Error("Wallet is not linked");
  const client = await oauthClient();
  try {
    const tokenSet = await client.refresh(decrypt(record.refresh_cipher));
    if (!tokenSet.access_token || !tokenSet.refresh_token) throw new Error("AS did not rotate the token pair");
    const claims = await validateUserAccessToken(tokenSet.access_token);
    if (claims.sub !== userId) throw new Error("Token subject does not match linked wallet");
    tokenDb.prepare("UPDATE linked_wallets SET refresh_cipher = ?, scope = ?, updated_at = ? WHERE user_id = ?").run(encrypt(tokenSet.refresh_token), tokenSet.scope || record.scope, now(), userId);
    return { accessToken: tokenSet.access_token, claims };
  } catch (error) {
    const oauthError = error.error || "";
    if (oauthError === "invalid_grant") {
      tokenDb.prepare("UPDATE linked_wallets SET status = 'unlinked', refresh_cipher = '', updated_at = ? WHERE user_id = ?").run(now(), userId);
    }
    throw error;
  }
}
async function walletFetch(accessToken, path, options) {
  const response = await fetch(config.apiBaseUrl + path, {
    ...options,
    headers: { ...(options && options.headers ? options.headers : {}), authorization: "Bearer " + accessToken },
    signal: AbortSignal.timeout(4000)
  });
  const body = await response.json().catch(function () { return { error: "invalid_response" }; });
  if (!response.ok) {
    const error = new Error(body.message || body.error || "Wallet API request failed");
    error.status = response.status;
    throw error;
  }
  return body;
}
async function runChargeJob() {
  const jobId = "job_" + crypto.randomUUID();
  const wallets = tokenDb.prepare("SELECT user_id FROM linked_wallets WHERE status = 'linked' ORDER BY user_id").all();
  const results = [];
  for (const wallet of wallets) {
    try {
      const fresh = await rotateRefreshToken(wallet.user_id);
      const charge = await walletFetch(fresh.accessToken, "/wallet/charges", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": stableJobKey(wallet.user_id) },
        body: JSON.stringify({ amount_minor: 25000 })
      });
      const details = { access_exp: new Date(fresh.claims.exp * 1000).toISOString(), charge_count: charge.charge_count, idempotent_replay: charge.idempotent_replay };
      logPayment(jobId, wallet.user_id, "charged", details);
      results.push({ user_id: wallet.user_id, status: "charged", ...details });
    } catch (error) {
      logPayment(jobId, wallet.user_id, "failed", { message: error.error || error.message || "unknown failure" });
      results.push({ user_id: wallet.user_id, status: "failed" });
    }
  }
  return { job_id: jobId, processed: results.length, results };
}
function hasJobKey(req) {
  const received = Buffer.from(req.get("x-job-key") || "");
  const expected = Buffer.from(config.jobKey);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(session({ name: "taxi_session", secret: config.sessionSecret, resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 8 * 60 * 60 * 1000 } }));
app.get("/health", function (_req, res) { res.json({ service: "taxi", status: "ok" }); });

app.get("/", function (req, res) {
  const userId = req.session.walletUserId;
  const linked = userId ? tokenDb.prepare("SELECT status, scope, updated_at FROM linked_wallets WHERE user_id = ?").get(userId) : undefined;
  const status = linked && linked.status === "linked"
    ? "<p class='good'>Wallet linked for subject <code>" + escapeHtml(userId) + "</code>. Refresh token is encrypted on Taxi server and never placed in this page.</p>"
    : "<p class='warn'>No active wallet is linked in this browser session.</p>";
  const actions = linked && linked.status === "linked"
    ? "<a class='button' href='/wallet/balance'>Read wallet balance</a><form style='display:inline' method='post' action='/demo/run-job'><button class='secondary' type='submit'>Run payment job demo</button></form><a class='button secondary' href='/logs'>View safe job logs</a>"
    : "<a class='button' href='/link-wallet'>Link Wallet with OAuth2</a>";
  res.send(page("Taxi", "<section class='card'><h1>Taxi · Wallet payment lab</h1>" + status + "<p>" + actions + "</p><p class='muted'>The scheduled endpoint uses an internal job key; its implementation does not depend on this browser session.</p></section>"));
});
app.get("/link-wallet", async function (req, res, next) {
  try {
    const client = await oauthClient();
    const codeVerifier = generators.codeVerifier();
    const state = generators.state();
    req.session.pkceVerifier = codeVerifier;
    req.session.oauthState = state;
    req.session.save(function (error) {
      if (error) return next(error);
      const url = client.authorizationUrl({
        response_type: "code",
        redirect_uri: config.baseUrl + "/oauth/callback",
        scope: "wallet:read wallet:charge offline_access",
        code_challenge: generators.codeChallenge(codeVerifier),
        code_challenge_method: "S256",
        state
      });
      res.redirect(302, url);
    });
  } catch (error) { next(error); }
});
app.get("/oauth/callback", async function (req, res, next) {
  try {
    if (!req.session.pkceVerifier || !req.session.oauthState) throw new Error("Missing OAuth browser state");
    const client = await oauthClient();
    const tokenSet = await client.oauthCallback(config.baseUrl + "/oauth/callback", req.query, { code_verifier: req.session.pkceVerifier, state: req.session.oauthState });
    delete req.session.pkceVerifier; delete req.session.oauthState;
    if (!tokenSet.access_token || !tokenSet.refresh_token) throw new Error("Expected access and refresh tokens");
    const claims = await validateUserAccessToken(tokenSet.access_token);
    tokenDb.prepare("INSERT INTO linked_wallets (user_id, refresh_cipher, scope, status, connected_at, updated_at) VALUES (?, ?, ?, 'linked', ?, ?) ON CONFLICT(user_id) DO UPDATE SET refresh_cipher = excluded.refresh_cipher, scope = excluded.scope, status = 'linked', updated_at = excluded.updated_at").run(claims.sub, encrypt(tokenSet.refresh_token), tokenSet.scope || "wallet:read wallet:charge offline_access", now(), now());
    req.session.walletUserId = claims.sub;
    req.session.save(function (error) { if (error) return next(error); res.redirect(302, "/"); });
  } catch (error) { next(error); }
});
app.get("/wallet/balance", async function (req, res, next) {
  try {
    if (!req.session.walletUserId) return res.redirect(302, "/");
    const fresh = await rotateRefreshToken(req.session.walletUserId);
    const balance = await walletFetch(fresh.accessToken, "/wallet/balance", { method: "GET" });
    res.send(page("Wallet balance", "<section class='card'><h1>Wallet balance</h1><p class='good'>Balance: <strong>" + escapeHtml(balance.balance_minor) + " VND</strong></p><p>Charge counter: <strong>" + escapeHtml(balance.charge_count) + "</strong></p><p class='muted'>The server refreshed the credential; neither access nor refresh token is rendered to the browser.</p><a class='button secondary' href='/'>Back</a></section>"));
  } catch (error) { next(error); }
});
app.post("/demo/run-job", async function (req, res, next) {
  try {
    if (!req.session.walletUserId) return res.redirect(302, "/");
    const result = await runChargeJob();
    res.send(page("Payment job", "<section class='card'><h1>Payment job completed</h1><pre>" + escapeHtml(JSON.stringify({ job_id: result.job_id, processed: result.processed, results: result.results }, null, 2)) + "</pre><p><a class='button secondary' href='/'>Back</a></p></section>"));
  } catch (error) { next(error); }
});
app.post("/jobs/charge", async function (req, res, next) {
  try {
    if (!hasJobKey(req)) return res.status(401).json({ error: "unauthorized_job_trigger" });
    res.json(await runChargeJob());
  } catch (error) { next(error); }
});
app.get("/logs", function (_req, res) {
  const rows = logDb.prepare("SELECT job_id, user_id, status, details, created_at FROM payment_logs ORDER BY created_at DESC LIMIT 20").all();
  const table = rows.length ? rows.map(function (row) {
    return "<tr><td>" + escapeHtml(row.created_at) + "</td><td>" + escapeHtml(row.user_id) + "</td><td>" + escapeHtml(row.status) + "</td><td><code>" + escapeHtml(row.details) + "</code></td></tr>";
  }).join("") : "<tr><td colspan='4'>No payment jobs yet.</td></tr>";
  res.send(page("Taxi job logs", "<section class='card'><h1>Safe payment logs</h1><p class='muted'>This is a separate SQLite file from encrypted refresh-token storage. Logs deliberately contain no authorization code, access token, refresh token, or session cookie.</p><table><thead><tr><th>Time</th><th>User</th><th>Status</th><th>Safe evidence</th></tr></thead><tbody>" + table + "</tbody></table><p><a class='button secondary' href='/'>Back</a></p></section>"));
});
app.use(function (error, _req, res, _next) {
  console.error("taxi request failed", error.error || error.message);
  if (!res.headersSent) res.status(500).send(page("Taxi error", "<section class='card'><h1>Taxi error</h1><p class='error'>The requested flow could not be completed. Inspect server logs; sensitive credentials are never logged.</p><a class='button secondary' href='/'>Back</a></section>"));
});
app.listen(config.port, "127.0.0.1", function () { console.log("Taxi listening on " + config.baseUrl); });
