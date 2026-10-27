import dotenv from "dotenv";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
dotenv.config({ path: resolve(root, "apps/wallet-as/.env.local") });
const asBaseUrl = process.env.WALLET_AS_BASE_URL || "http://127.0.0.1:3001";
const taxiBaseUrl = process.env.TAXI_BASE_URL || "http://127.0.0.1:3003";
const webSecret = process.env.TAXI_WEB_CLIENT_SECRET;
const m2mSecret = process.env.TAXI_M2M_CLIENT_SECRET;
const includeExpiry = !process.argv.includes("--skip-expiry");
if (!webSecret || !m2mSecret) throw new Error("Run npm run setup:local before attack tests.");

function verifier() { return randomBytes(32).toString("base64url"); }
function challenge(value) { return createHash("sha256").update(value).digest("base64url"); }
function basic(clientId, secret) { return "Basic " + Buffer.from(clientId + ":" + secret).toString("base64"); }
function wait(milliseconds) { return new Promise(function (resolveWait) { setTimeout(resolveWait, milliseconds); }); }
function form(values) { return new URLSearchParams(values).toString(); }

class CookieJar {
  constructor() { this.value = ""; }
  add(response) {
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) this.value = setCookie.split(";")[0];
  }
  async fetch(url, options) {
    const headers = new Headers((options && options.headers) || {});
    if (this.value) headers.set("cookie", this.value);
    const response = await fetch(url, { ...(options || {}), headers, redirect: "manual" });
    this.add(response);
    return response;
  }
}

async function responseInfo(response) {
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : {};
  return { status: response.status, error: body.error || null, location: response.headers.get("location") || null };
}
function result(name, info, expectedStatus, expectedError) {
  const pass = info.status === expectedStatus && (!expectedError || info.error === expectedError);
  return { name, pass, got: { status: info.status, error: info.error }, expected: { status: expectedStatus, error: expectedError || null } };
}
async function tokenRequest(clientId, secret, values) {
  return fetch(asBaseUrl + "/token", {
    method: "POST",
    headers: { authorization: basic(clientId, secret), "content-type": "application/x-www-form-urlencoded" },
    body: form(values),
    redirect: "manual"
  });
}
async function authorizeCode(codeVerifier) {
  const jar = new CookieJar();
  const start = new URL(asBaseUrl + "/authorize");
  start.search = new URLSearchParams({
    response_type: "code",
    client_id: "taxi-web",
    redirect_uri: taxiBaseUrl + "/oauth/callback",
    scope: "wallet:read wallet:charge offline_access",
    code_challenge: challenge(codeVerifier),
    code_challenge_method: "S256",
    state: randomBytes(12).toString("base64url")
  }).toString();
  let response = await jar.fetch(start, { method: "GET" });
  if (response.status !== 302 || response.headers.get("location") !== "/login") throw new Error("Authorization did not reach login page");
  response = await jar.fetch(asBaseUrl + "/login", { method: "GET" });
  if (response.status !== 200) throw new Error("Login page unavailable");
  response = await jar.fetch(asBaseUrl + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: "alice", password: "alice-password" })
  });
  if (response.status !== 302 || response.headers.get("location") !== "/consent") throw new Error("Lab login failed");
  response = await jar.fetch(asBaseUrl + "/consent", { method: "GET" });
  if (response.status !== 200) throw new Error("Consent page unavailable");
  response = await jar.fetch(asBaseUrl + "/consent", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ decision: "approve" })
  });
  const location = response.headers.get("location");
  const code = location ? new URL(location).searchParams.get("code") : null;
  if (response.status !== 302 || !code) throw new Error("Consent did not return an authorization code");
  return code;
}
async function freshTokens() {
  const value = verifier();
  const code = await authorizeCode(value);
  const response = await tokenRequest("taxi-web", webSecret, {
    grant_type: "authorization_code",
    code,
    redirect_uri: taxiBaseUrl + "/oauth/callback",
    code_verifier: value
  });
  const body = await response.json();
  if (response.status !== 200 || !body.refresh_token || !body.access_token) throw new Error("Cannot obtain lab token pair for attack test");
  return body;
}

const results = [];
const badRedirect = new URL(asBaseUrl + "/authorize");
badRedirect.search = new URLSearchParams({
  response_type: "code", client_id: "taxi-web", redirect_uri: "http://attacker.invalid/callback",
  scope: "wallet:read", code_challenge: challenge(verifier()), code_challenge_method: "S256"
}).toString();
const badRedirectResponse = await fetch(badRedirect, { redirect: "manual" });
const badRedirectInfo = await responseInfo(badRedirectResponse);
const badRedirectPass = badRedirectInfo.status === 400 && !badRedirectInfo.location;
results.push({ name: "unregistered redirect_uri stays at AS", pass: badRedirectPass, got: { status: badRedirectInfo.status, location_present: Boolean(badRedirectInfo.location) }, expected: { status: 400, location_present: false } });

const missingPkce = new URL(asBaseUrl + "/authorize");
missingPkce.search = new URLSearchParams({
  response_type: "code", client_id: "taxi-web", redirect_uri: taxiBaseUrl + "/oauth/callback", scope: "wallet:read", state: "missing-pkce"
}).toString();
const missingPkceResponse = await fetch(missingPkce, { redirect: "manual" });
const missingPkceInfo = await responseInfo(missingPkceResponse);
const missingPkceError = missingPkceInfo.location ? new URL(missingPkceInfo.location).searchParams.get("error") : null;
results.push({ name: "missing PKCE challenge", pass: missingPkceInfo.status === 302 && missingPkceError === "invalid_request", got: { status: missingPkceInfo.status, error: missingPkceError }, expected: { status: 302, error: "invalid_request" } });

const wrongSecretVerifier = verifier();
const wrongSecretCode = await authorizeCode(wrongSecretVerifier);
results.push(result("wrong client secret", await responseInfo(await tokenRequest("taxi-web", "not-the-secret", {
  grant_type: "authorization_code", code: wrongSecretCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: wrongSecretVerifier
})), 401, "invalid_client"));

const reusedVerifier = verifier();
const reusedCode = await authorizeCode(reusedVerifier);
const firstExchange = await responseInfo(await tokenRequest("taxi-web", webSecret, {
  grant_type: "authorization_code", code: reusedCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: reusedVerifier
}));
results.push(result("first authorization-code exchange", firstExchange, 200));
results.push(result("authorization-code replay", await responseInfo(await tokenRequest("taxi-web", webSecret, {
  grant_type: "authorization_code", code: reusedCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: reusedVerifier
})), 400, "invalid_grant"));

const wrongVerifier = verifier();
const wrongVerifierCode = await authorizeCode(wrongVerifier);
results.push(result("wrong PKCE verifier", await responseInfo(await tokenRequest("taxi-web", webSecret, {
  grant_type: "authorization_code", code: wrongVerifierCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: verifier()
})), 400, "invalid_grant"));

const otherClientVerifier = verifier();
const otherClientCode = await authorizeCode(otherClientVerifier);
results.push(result("authorization code exchanged by another client", await responseInfo(await tokenRequest("taxi-m2m", m2mSecret, {
  grant_type: "authorization_code", code: otherClientCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: otherClientVerifier
})), 400, "unauthorized_client"));

const replayPair = await freshTokens();
const refreshOnce = await responseInfo(await tokenRequest("taxi-web", webSecret, {
  grant_type: "refresh_token", refresh_token: replayPair.refresh_token
}));
results.push(result("first refresh rotation", refreshOnce, 200));
results.push(result("refresh-token replay revokes family", await responseInfo(await tokenRequest("taxi-web", webSecret, {
  grant_type: "refresh_token", refresh_token: replayPair.refresh_token
})), 400, "invalid_grant"));

const otherClientPair = await freshTokens();
results.push(result("refresh with another client", await responseInfo(await tokenRequest("taxi-m2m", m2mSecret, {
  grant_type: "refresh_token", refresh_token: otherClientPair.refresh_token
})), 400, "unauthorized_client"));

results.push(result("M2M asks for wallet:charge", await responseInfo(await tokenRequest("taxi-m2m", m2mSecret, {
  grant_type: "client_credentials", scope: "wallet:charge"
})), 400, "invalid_scope"));

const machineTokenResponse = await tokenRequest("taxi-m2m", m2mSecret, { grant_type: "client_credentials", scope: "rates:read" });
const machineTokens = await machineTokenResponse.json();
const machineRates = await fetch((process.env.WALLET_API_BASE_URL || "http://127.0.0.1:3002") + "/public/rates", { headers: { authorization: "Bearer " + machineTokens.access_token } });
results.push({ name: "M2M can read public rates", pass: machineTokenResponse.status === 200 && machineRates.status === 200, got: { token_status: machineTokenResponse.status, api_status: machineRates.status }, expected: { token_status: 200, api_status: 200 } });
const machineCharge = await fetch((process.env.WALLET_API_BASE_URL || "http://127.0.0.1:3002") + "/wallet/charges", {
  method: "POST",
  headers: { authorization: "Bearer " + machineTokens.access_token, "content-type": "application/json", "idempotency-key": "m2m-attack-key" },
  body: JSON.stringify({ amount_minor: 1000 })
});
results.push({ name: "M2M token cannot charge wallet", pass: machineCharge.status === 403, got: { status: machineCharge.status }, expected: { status: 403 } });

if (includeExpiry) {
  const expiringVerifier = verifier();
  const expiringCode = await authorizeCode(expiringVerifier);
  console.log("Waiting 61 seconds to test the configured 60-second code TTL...");
  await wait(61000);
  results.push(result("expired authorization code", await responseInfo(await tokenRequest("taxi-web", webSecret, {
    grant_type: "authorization_code", code: expiringCode, redirect_uri: taxiBaseUrl + "/oauth/callback", code_verifier: expiringVerifier
  })), 400, "invalid_grant"));
}

const output = { generated_at: new Date().toISOString(), as_url: asBaseUrl, include_expiry: includeExpiry, results };
mkdirSync(resolve(root, "evidence"), { recursive: true });
writeFileSync(resolve(root, "evidence/attack-results-after.json"), JSON.stringify(output, null, 2) + "\n", "utf8");
for (const item of results) console.log((item.pass ? "PASS" : "FAIL") + "  " + item.name + "  expected=" + JSON.stringify(item.expected) + " got=" + JSON.stringify(item.got));
console.log("Wrote sanitized evidence/attack-results-after.json. No code or token values were printed.");
if (results.some(function (item) { return !item.pass; })) process.exitCode = 1;
