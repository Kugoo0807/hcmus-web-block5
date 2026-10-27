import express from "express";
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error("Missing required environment variable: " + name);
  return value;
}
const config = {
  baseUrl: required("WALLET_API_BASE_URL"),
  asBaseUrl: required("WALLET_AS_BASE_URL"),
  port: Number(process.env.WALLET_API_PORT || 3002),
  dbPath: process.env.WALLET_API_DB_PATH || resolve(root, "apps/wallet-api/data/wallet-api.sqlite")
};
mkdirSync(dirname(config.dbPath), { recursive: true });
const db = new DatabaseSync(config.dbPath);
db.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;");
db.exec([
  "CREATE TABLE IF NOT EXISTS accounts (user_id TEXT PRIMARY KEY, balance_minor INTEGER NOT NULL, charge_count INTEGER NOT NULL DEFAULT 0);",
  "CREATE TABLE IF NOT EXISTS charges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, amount_minor INTEGER NOT NULL, created_at TEXT NOT NULL, UNIQUE(user_id, idempotency_key));"
].join("\n"));

const jwks = createRemoteJWKSet(new URL(config.asBaseUrl + "/.well-known/jwks.json"));
function now() { return new Date().toISOString(); }
function jsonError(res, status, error, message) { return res.status(status).json({ error, message }); }
function parseScopes(payload) {
  return typeof payload.scope === "string" ? payload.scope.split(/\s+/).filter(Boolean) : [];
}
async function rejectedJtis() {
  const response = await fetch(config.asBaseUrl + "/internal/revocations", { signal: AbortSignal.timeout(2000) });
  if (!response.ok) throw new Error("Cannot obtain code-replay revocation list");
  const body = await response.json();
  return new Set(Array.isArray(body.revoked_jtis) ? body.revoked_jtis : []);
}
async function authenticate(req) {
  const header = req.get("authorization") || "";
  if (!header.startsWith("Bearer ")) throw new Error("missing_bearer_token");
  const token = header.slice(7);
  const verified = await jwtVerify(token, jwks, {
    issuer: config.asBaseUrl,
    audience: "wallet-api",
    algorithms: ["ES256"]
  });
  const payload = verified.payload;
  if (typeof payload.sub !== "string" || typeof payload.client_id !== "string" || typeof payload.principal_type !== "string" || typeof payload.jti !== "string") throw new Error("malformed_claims");
  if ((await rejectedJtis()).has(payload.jti)) throw new Error("revoked_after_code_replay");
  return payload;
}
function needs(scope, principalType) {
  return async function (req, res, next) {
    try {
      const payload = await authenticate(req);
      if (!parseScopes(payload).includes(scope)) return jsonError(res, 403, "insufficient_scope", "Required scope: " + scope);
      if (principalType && payload.principal_type !== principalType) return jsonError(res, 403, "insufficient_principal", "This endpoint requires a user token");
      req.accessToken = payload;
      return next();
    } catch (error) {
      if (error.message === "missing_bearer_token") return jsonError(res, 401, "invalid_token", "Bearer token required");
      if (error.message === "revoked_after_code_replay") return jsonError(res, 401, "invalid_token", "Token was revoked after authorization-code replay");
      console.error("token rejected", error.code || error.message);
      return jsonError(res, 401, "invalid_token", "Token signature, issuer, audience, expiry, or required claims are invalid");
    }
  };
}
function ensureAccount(userId) {
  db.prepare("INSERT INTO accounts (user_id, balance_minor, charge_count) VALUES (?, ?, 0) ON CONFLICT(user_id) DO NOTHING").run(userId, 1000000);
  return db.prepare("SELECT * FROM accounts WHERE user_id = ?").get(userId);
}
function randomChargeId() {
  return "charge_" + crypto.randomUUID();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.get("/health", function (_req, res) { res.json({ service: "wallet-api", status: "ok" }); });

app.get("/wallet/balance", needs("wallet:read", "user"), function (req, res) {
  const account = ensureAccount(req.accessToken.sub);
  res.json({ owner_sub: req.accessToken.sub, currency: "VND", balance_minor: account.balance_minor, charge_count: account.charge_count });
});

app.post("/wallet/charges", needs("wallet:charge", "user"), function (req, res) {
  const key = req.get("idempotency-key") || "";
  const amount = req.body && req.body.amount_minor;
  if (key.length < 8 || key.length > 200) return jsonError(res, 400, "invalid_request", "A stable Idempotency-Key (8-200 chars) is required");
  if (!Number.isSafeInteger(amount) || amount <= 0 || amount > 500000) return jsonError(res, 400, "invalid_request", "amount_minor must be a positive integer up to 500000");

  db.exec("BEGIN IMMEDIATE");
  try {
    const prior = db.prepare("SELECT * FROM charges WHERE user_id = ? AND idempotency_key = ?").get(req.accessToken.sub, key);
    if (prior) {
      const account = ensureAccount(req.accessToken.sub);
      db.exec("COMMIT");
      return res.json({ charge_id: prior.id, amount_minor: prior.amount_minor, balance_minor: account.balance_minor, charge_count: account.charge_count, idempotent_replay: true });
    }
    const account = ensureAccount(req.accessToken.sub);
    if (account.balance_minor < amount) {
      db.exec("ROLLBACK");
      return jsonError(res, 409, "insufficient_funds", "Wallet balance is too low");
    }
    const chargeId = randomChargeId();
    db.prepare("INSERT INTO charges (id, user_id, idempotency_key, amount_minor, created_at) VALUES (?, ?, ?, ?, ?)").run(chargeId, req.accessToken.sub, key, amount, now());
    db.prepare("UPDATE accounts SET balance_minor = balance_minor - ?, charge_count = charge_count + 1 WHERE user_id = ?").run(amount, req.accessToken.sub);
    const updated = db.prepare("SELECT * FROM accounts WHERE user_id = ?").get(req.accessToken.sub);
    db.exec("COMMIT");
    return res.status(201).json({ charge_id: chargeId, amount_minor: amount, balance_minor: updated.balance_minor, charge_count: updated.charge_count, idempotent_replay: false });
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch {}
    console.error("charge failed", error.message);
    return jsonError(res, 500, "server_error", "Charge could not be processed");
  }
});

app.get("/public/rates", needs("rates:read"), function (_req, res) {
  res.json({ currency: "VND", base_fare_minor: 15000, per_km_minor: 9000, published_at: now() });
});

app.use(function (_req, res) { jsonError(res, 404, "not_found", "Route not found"); });
app.listen(config.port, "127.0.0.1", function () { console.log("Wallet API listening on " + config.baseUrl); });
